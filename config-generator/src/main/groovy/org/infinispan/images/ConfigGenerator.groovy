package org.infinispan.images


import groovy.text.SimpleTemplateEngine
import groovy.text.TemplateEngine
import groovy.text.XmlTemplateEngine
import groovy.xml.XmlUtil
import org.yaml.snakeyaml.Yaml

import java.security.MessageDigest

static Map mergeMaps(Map lhs, Map rhs) {
    rhs.each { k, v -> lhs[k] = lhs[k] in Map ? mergeMaps(lhs[k], v) : v }
    lhs
}

static void printErrorAndExit(String error) {
    System.err.println error
    System.exit 1
}

static String addSeparator(String path) {
    return path.endsWith(File.separator) ? path : "${path}${File.separator}"
}

static void exec(String cmd) {
    Process process = cmd.execute()
    process.waitForProcessOutput System.out, System.err
    def exitValue = process.exitValue()
    if (exitValue) System.exit exitValue
}

static void processXmlTemplate(String templateName, String dest, Map binding) {
    processTemplate new XmlTemplateEngine(), templateName, dest, binding
}

static void processXmlTemplate(InputStream template, String dest, Map binding) {
    processTemplate new XmlTemplateEngine(), template, dest, binding
}

static void processPropertiesTemplate(String templateName, String dest, Map binding) {
    processTemplate new SimpleTemplateEngine(), templateName, dest, binding
}

static void processTemplate(TemplateEngine engine, String templateName, String dest, Map binding) {
    processTemplate engine, ConfigGenerator.classLoader.getResourceAsStream(templateName), dest, binding
}

static void processTemplate(TemplateEngine engine, InputStream template, String dest, Map binding) {
    engine.createTemplate(template.text)
            .make(binding)
            .writeTo(new File(dest).newWriter())
}

static void configureKeystore(ks, String outputDir) {
    if (!ks.path?.trim() && !ks.crtPath?.trim()) {
        if (ks.selfSignCert) {
            ks.password = "infinispan"
            ks.path = "${outputDir}selfsigned_keystore.p12"
            ks.alias = "server"
        }
        return
    }

    // If path is defined then ignore selfSignCert
    ks.selfSignCert = false

    // If ks.path == null then use default for keystore
    def ksRoot = ks.path == null ? new File("${outputDir}keystores") : new File(ks.path).parentFile
    ksRoot.mkdirs()
    ksRoot = addSeparator ksRoot.getAbsolutePath()

    // If user provides a key/cert in ks.crtPath then build
    // a keystore from them and store it in ks.path (overwriting
    // any eventual content in ks.path)
    if (ks.crtPath != null) {
        String crtSrc = addSeparator((String) ks.crtPath)
        String ksPkcs = "${ksRoot}keystore.pkcs12"

        // Add values to the map so they can be used in the templates
        ks.path = ks.path ?: "${ksRoot}keystore.p12"
        ks.password = ks.password ?: "infinispan"

        exec "openssl pkcs12 -export -inkey ${crtSrc}tls.key -in ${crtSrc}tls.crt -out ${ksPkcs} -name ${ks.alias} -password pass:${ks.password}"

        exec "keytool -importkeystore -noprompt -srckeystore ${ksPkcs} -srcstoretype pkcs12 -srcstorepass ${ks.password} -srcalias ${ks.alias} " +
                "-destalias ${ks.alias} -destkeystore ${ks.path} -deststoretype pkcs12 -storepass ${ks.password}"
    }
}

static void processCredentials(credentials, String outputDir, realm = "default") {
    if (!credentials) return

    def (users, groups) = [new Properties(), new Properties()]
    credentials.each { c ->
        if (!c.username || !c.password) printErrorAndExit "Credential identities require both a 'username' and 'password'"

        if (c.preDigestedPassword) {
            users.put c.username, c.password
        } else {
            MessageDigest md5 = MessageDigest.getInstance "MD5"
            String hash = md5.digest("${c.username}:${realm}:${c.password}".getBytes("UTF-8")).encodeHex().toString()
            users.put c.username, hash
        }

        if (c.roles) groups.put c.username, c.roles.join(",")
    }
    users.store new File("${outputDir}users.properties").newWriter(), "\$REALM_NAME=${realm}\$"
    groups.store new File("${outputDir}groups.properties").newWriter(), null
}

static void processIdentities(Map identities, String outputDir) {
    processCredentials identities.credentials, outputDir
}

static void processInfinispanConfig(String destDir, Map configYaml, String cacheConfigXml) {
    def xmlParser = new XmlParser()
    def infinispanConfig = xmlParser.parse(ConfigGenerator.classLoader.getResourceAsStream("infinispan.xml"))
    if (cacheConfigXml) {
        def cacheConfig = xmlParser.parseText(cacheConfigXml)
        infinispanConfig.'cache-container'[0].replaceNode(cacheConfig)
    }
    processXmlTemplate new ByteArrayInputStream(XmlUtil.serialize(infinispanConfig).bytes), destDir, configYaml
}

if (args.length < 2) printErrorAndExit 'Usage: OUTPUT_DIR IDENTITIES_YAML <CONFIG_YAML> <CONFIG_CACHE_XML>'

def outputDir = addSeparator args[0]
Map identitiesYaml = new Yaml().load(new File(args[1]).newInputStream())
Map defaultConfig = new Yaml().load(ConfigGenerator.classLoader.getResourceAsStream('default-config.yaml'))

// Process Identities
processIdentities identitiesYaml, outputDir

// Add bindAddress to defaults
defaultConfig.jgroups.bindAddress = InetAddress.localHost.hostAddress

// If no user config then use defaults, otherwise load user config and add default values for missing elements
Map configYaml = args.length == 2 || args[2].empty ? defaultConfig : mergeMaps(defaultConfig, new Yaml().load(new File(args[2]).newInputStream()))

configureKeystore configYaml.keystore, outputDir
// Generate JGroups stack files
def transport = configYaml.jgroups.transport
processXmlTemplate "jgroups-${transport}.xml", "${outputDir}jgroups-${transport}.xml", configYaml
if (configYaml.xsite?.backups) processXmlTemplate "jgroups-relay.xml", "${outputDir}jgroups-relay.xml", configYaml

def cacheConfig = args.length == 4 && !args[3].empty ? new File(args[3]).text : null

// Generate Infinispan configuration
processInfinispanConfig "${outputDir}infinispan.xml", configYaml, cacheConfig

// Generate Logging configuration
processPropertiesTemplate 'logging.properties', "${outputDir}logging.properties", configYaml
