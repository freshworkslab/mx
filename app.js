const express = require('express');
const bodyParser = require('body-parser');
const whois = require('whois');
const dns = require('dns').promises;
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Email providers array
const emailProviders = [
    { pattern: 'google', name: 'Google', aliases: ['googlemail', 'gmail', 'aspmx.l.google.com','googlemail.com', 'google.com'] },
    { pattern: 'outlook', name: 'Microsoft Outlook', aliases: ['protection.outlook.com', 'mail.protection.outlook.com', 'microsoft365.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com'] },
    { pattern: 'sendgrid', name: 'SendGrid', aliases: ['sendgrid.net', 'smtp.sendgrid.net'] },
    { pattern: 'mailgun', name: 'Mailgun', aliases: ['mailgun.org', 'smtp.mailgun.org'] },
    { pattern: 'yahoo', name: 'Yahoo Mail', aliases: ['yahoodns.net', 'yahoo.com', 'yahoo-inc.com', 'ymail.com', 'rocketmail.com'] },
    { pattern: 'zoho', name: 'Zoho Mail', aliases: ['zoho.com', 'zoho.eu', 'zohomail.com'] },
    { pattern: 'icloud', name: 'Apple iCloud Mail', aliases: ['icloud.com', 'me.com', 'mac.com'] },
    { pattern: 'protonmail', name: 'ProtonMail', aliases: ['protonmail.com', 'proton.me', 'pm.me'] },
    { pattern: 'yandex', name: 'Yandex Mail', aliases: ['yandex.net', 'yandex.com', 'yandex.ru', 'yandex.ua', 'yandex.kz', 'yandex.by'] },
    { pattern: 'aol', name: 'AOL Mail', aliases: ['aol.com', 'aim.com', 'aol.net'] },
    { pattern: 'fastmail', name: 'Fastmail', aliases: ['fastmail.com', 'messagingengine.com', 'fastmail.fm'] },
    { pattern: 'mail.com', name: 'Mail.com', aliases: ['mail.com', 'gmx.com', 'gmx.net'] },
    { pattern: 'qq', name: 'QQ Mail', aliases: ['qq.com', 'mx3.qq.com'] },
    { pattern: '163', name: 'NetEase 163 Mail', aliases: ['163.com', 'mx.163.com'] },
    { pattern: '126', name: 'NetEase 126 Mail', aliases: ['126.com', 'mx.126.com'] },
    { pattern: 'hushmail', name: 'Hushmail', aliases: ['hushmail.com', 'hush.com'] },
    { pattern: 'gmx', name: 'GMX Mail', aliases: ['gmx.com', 'gmx.net', 'gmx.de'] },
    { pattern: 'tutanota', name: 'Tutanota', aliases: ['tutanota.com', 'tutamail.com', 'tuta.io'] },
    { pattern: 'hey', name: 'Hey.com', aliases: ['hey.com'] },
    { pattern: 'mailfence', name: 'Mailfence', aliases: ['mailfence.com'] },
    { pattern: 'runbox', name: 'Runbox', aliases: ['runbox.com', 'runbox.no'] },
    { pattern: 'lycos', name: 'Lycos Mail', aliases: ['lycos.com'] },
    { pattern: 'earthlink', name: 'EarthLink', aliases: ['earthlink.net'] },
    { pattern: 'comcast', name: 'Comcast', aliases: ['comcast.net'] },
    { pattern: 'verizon', name: 'Verizon', aliases: ['verizon.net'] },
    { pattern: 'att', name: 'AT&T Mail', aliases: ['att.net', 'sbcglobal.net', 'bellsouth.net', 'pacbell.net'] },
    { pattern: 'shaw', name: 'Shaw Webmail', aliases: ['shaw.ca'] },
    { pattern: 'btinternet', name: 'BT Internet', aliases: ['btinternet.com', 'bt.com'] },
    { pattern: 'virginmedia', name: 'Virgin Media', aliases: ['virginmedia.com'] },
    { pattern: 'orange', name: 'Orange Mail', aliases: ['orange.fr'] },
    { pattern: 't-online', name: 'T-Online', aliases: ['t-online.de'] },
    { pattern: 'freenet', name: 'Freenet Mail', aliases: ['freenet.de'] },
    { pattern: 'web.de', name: 'WEB.DE', aliases: ['web.de'] },
    { pattern: 'mail.ru', name: 'Mail.ru', aliases: ['mail.ru', 'inbox.ru', 'bk.ru', 'list.ru'] },
    { pattern: 'seznam', name: 'Seznam.cz', aliases: ['seznam.cz', 'email.cz', 'post.cz'] },
    { pattern: 'laposte', name: 'La Poste', aliases: ['laposte.net'] },
    { pattern: 'bluewin', name: 'Bluewin', aliases: ['bluewin.ch'] },
    { pattern: 'sfr', name: 'SFR Mail', aliases: ['sfr.fr'] },
    { pattern: 'alice', name: 'Alice Mail', aliases: ['alice.it'] },
    { pattern: 'libero', name: 'Libero Mail', aliases: ['libero.it', 'iol.it', 'blu.it', 'inwind.it', 'virgilio.it'] },
    { pattern: 'cox', name: 'Cox Communications', aliases: ['cox.net'] },
    { pattern: 'telus', name: 'Telus', aliases: ['telus.net'] },
    { pattern: 'rogers', name: 'Rogers', aliases: ['rogers.com'] },
    { pattern: 'bell', name: 'Bell', aliases: ['bell.net'] },
    { pattern: 'uol', name: 'UOL Mail', aliases: ['uol.com.br'] },
    { pattern: 'terra', name: 'Terra', aliases: ['terra.com', 'terra.com.br', 'terra.es', 'terra.cl'] },
    { pattern: 'prodigy', name: 'Prodigy (Telmex)', aliases: ['prodigy.net.mx'] },
    { pattern: 'nifty', name: 'Nifty', aliases: ['nifty.com'] },
    { pattern: 'bigpond', name: 'BigPond', aliases: ['bigpond.com', 'bigpond.net.au', 'telstra.com'] },
    { pattern: 'singnet', name: 'SingNet', aliases: ['singnet.com.sg'] },
    { pattern: 'cloudflare', name: 'Cloudflare Email', aliases: ['cloudflare.com', 'mail.cloudflare.com'] },
    { pattern: 'fastly', name: 'Fastly Email', aliases: ['fastly.com'] },
    { pattern: 'ovh', name: 'OVH Email', aliases: ['ovh.com'] },
    { pattern: 'nexmo', name: 'Nexmo Email', aliases: ['nexmo.com'] },
    { pattern: 'mailjet', name: 'Mailjet', aliases: ['mailjet.com'] },
    { pattern: 'postmark', name: 'Postmark', aliases: ['postmarkapp.com'] },
    { pattern: 'socketlabs', name: 'SocketLabs', aliases: ['socketlabs.com'] },
    { pattern: 'mandrill', name: 'Mandrill', aliases: ['mandrill.com'] },
    { pattern: 'rid-spam', name: 'Rid-Spam', aliases: ['rid-spam.com', 'protect.rid-spam.com'] },

    // Add more providers as needed...
];

// Add help articles for DNS hosting providers
const helpArticles = {
    'Amazon Web Services (AWS)': 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#CNAMEFormat',
    'Cloudflare': 'https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/',
    'DigitalOcean': 'https://www.digitalocean.com/docs/networking/dns/how-to/manage-dns-records/',
    'GoDaddy': 'https://www.godaddy.com/help/add-an-a-record-680',
    'Google Cloud DNS': 'https://cloud.google.com/dns/docs/quickstart',
    'Bluehost': 'https://www.bluehost.com/help/article/how-to-add-dns-records',
    'HostGator': 'https://www.hostgator.com/help/article/how-to-add-a-dns-record',
    'Namecheap': 'https://www.namecheap.com/support/knowledgebase/article.aspx/434/2237/how-do-i-set-up-host-records-for-a-domain/',
    'Microsoft Azure': 'https://docs.microsoft.com/en-us/azure/dns/dns-records',
    'OVH': 'https://docs.ovh.com/us/en/domains/how-to-manage-dns-records/',
    'Linode': 'https://www.linode.com/docs/guides/manage-dns-with-the-linode-manager/',
    'DreamHost': 'https://help.dreamhost.com/hc/en-us/articles/215669158-How-do-I-add-a-DNS-record-',
    'SiteGround': 'https://www.siteground.com/kb/how-to-edit-dns-zone-file/',
    'WP Engine': 'https://wpengine.com/support/dns-records/',
    '1&1 IONOS': 'https://www.ionos.com/digitalguide/websites/web-development/dns-records/',
    'Hetzner': 'https://docs.hetzner.cloud/en/knowledge-base/setting-dns-records/',
    'Vultr': 'https://www.vultr.com/docs/how-to-set-up-dns-using-vultr-dns/',
    'Fastly': 'https://developer.fastly.com/reference/api/services/#create-a-domain',
    'Netlify': 'https://docs.netlify.com/domains-https/custom-domains/configure-external-dns/',
    'Vercel': 'https://vercel.com/docs/custom-domains#using-external-dns',
    'Rackspace': 'https://docs.rackspace.com/support/how-to/manage-dns-records/',
    'NS1': 'https://ns1.com/docs/dns/overview',
    'Nexcess': 'https://www.nexcess.net/support/knowledgebase/manage-dns-records-nexcess/',
    'Gandi': 'https://docs.gandi.net/en/domain/how_to/manage_records',
    'Porkbun': 'https://porkbun.com/support/knowledgebase/how-to-create-a-dns-record',
    'Name.com': 'https://www.name.com/support/articles/114032385132-How-do-I-add-a-DNS-record-',
    'TSOHost': 'https://www.tsohost.com/knowledgebase/articles/4158-how-to-set-up-dns-records',
    'Hostinger': 'https://www.hostinger.com/tutorials/how-to-set-up-dns-records',
    'Crazy Domains': 'https://www.crazydomains.com.au/support/how-to-manage-dns-records/',
    'InMotion Hosting': 'https://www.inmotionhosting.com/support/website/how-to-manage-dns-records-in-cpanel/',
    'A2 Hosting': 'https://www.a2hosting.com/kb/article/how-to-add-dns-records-in-cpanel/',
    'FastDNS': 'https://www.fastdns.com/docs/how-to-manage-your-dns-records/',
    'HostPapa': 'https://www.hostpapa.com/kb/how-to-add-dns-records-to-your-hostpapa-account/',
    'Network Solutions': 'https://www.networksolutions.com/support/how-to-update-dns-records/',
    'DomainDiscover': 'https://www.domaindiscover.com/support/manage-dns-records',
    'NameBright': 'https://www.namebright.com/faq/manage-domain-dns-settings',
    'Dotster': 'https://www.dotster.com/help/how-to-add-dns-records',
    'GKG.net': 'https://www.gkg.net/help/knowledgebase/article/2408/how-to-add-a-dns-record',
    'Register.com': 'https://www.register.com/support/articles/dns-records',
    'DreamHost': 'https://help.dreamhost.com/hc/en-us/articles/215669158-How-do-I-add-a-DNS-record-',
    'Wix.com': 'https://support.wix.com/en/article/managing-dns-records-in-your-wix-account',
};

// Add useful links section
const usefulLinks = {
    'DNS Tools': [
        { name: 'MXToolbox', url: 'https://mxtoolbox.com/', description: 'Comprehensive DNS and email testing tools' },
        { name: 'Google Admin Toolbox', url: 'https://toolbox.googleapps.com/apps/checkmx/', description: 'Check MX record configuration' },
        { name: 'DNS Checker', url: 'https://dnschecker.org/', description: 'Global DNS propagation checker' }
    ],
    'Email Security': [
        { name: 'DMARC Guide', url: 'https://dmarc.org/overview/', description: 'DMARC implementation guide' },
        { name: 'SPF Record Testing', url: 'https://www.spf-record.com/', description: 'Test and validate SPF records' },
        { name: 'DKIM Core', url: 'https://dkim.org/', description: 'DKIM implementation resources' }
    ],
    'Domain Management': [
        { name: 'ICANN Lookup', url: 'https://lookup.icann.org/', description: 'Official ICANN domain lookup' },
        { name: 'SSL Labs', url: 'https://www.ssllabs.com/ssltest/', description: 'SSL/TLS configuration testing' }
    ]
};

// Route for the home page (GET)
app.get('/', (req, res) => {
    const viewData = {
        provider: null,
        possibleProviders: [],
        mxRecords: [],
        spfRecord: null,
        dmarcRecord: null,
        nsRecords: [],
        dnsHostingInfo: [],
        error: null,
        helpArticles: helpArticles,
        usefulLinks: usefulLinks
    };
    res.render('index', viewData);
});

// Route to handle form submission for DNS hosting provider lookup
app.post('/lookup', async (req, res) => {
    const input = req.body.input;
    const domain = input.includes('@') ? input.split('@')[1] : input;

    try {
        const emailResult = await getEmailProvider(domain);
        const nameServers = await fetchNameServers(domain);
        const registrar = await fetchRegistrar(domain);
        const hostingProviders = nameServers.map(ns => fetchHostingProvider(ns)).join('<br>');

        const viewData = {
            provider: emailResult.primaryProvider,
            possibleProviders: emailResult.possibleProviders,
            mxRecords: emailResult.mxRecords,
            spfRecord: emailResult.spfRecord,
            dmarcRecord: emailResult.dmarcRecord,
            nsRecords: nameServers,
            dnsHostingInfo: hostingProviders,
            registrar: registrar,
            helpArticles: helpArticles,
            usefulLinks: usefulLinks,
            error: emailResult.error || null
        };
        return res.render('index', viewData);
    } catch (error) {
        const errorViewData = {
            provider: null,
            possibleProviders: [],
            mxRecords: [],
            spfRecord: null,
            dmarcRecord: null,
            nsRecords: [],
            dnsHostingInfo: [],
            registrar: 'Unknown',
            helpArticles: helpArticles,
            usefulLinks: usefulLinks,
            error: `Error processing request: ${error.message}`
        };
        return res.render('index', errorViewData);
    }
});

// Function to fetch name servers for the given domain
async function fetchNameServers(domain) {
    try {
        const nameServers = await dns.resolveNs(domain);
        console.log(`Name Servers for ${domain}:`, nameServers);
        return nameServers;
    } catch (err) {
        console.error(`Error fetching name servers for ${domain}:`, err);
        return [];
    }
}

// Function to fetch registrar information for the given domain
function fetchRegistrar(domain) {
    return new Promise((resolve, reject) => {
        whois.lookup(domain, (err, data) => {
            if (err) {
                console.error(`Error fetching WHOIS data for ${domain}:`, err);
                resolve('Unknown Registrar');
                return;
            }

            const registrarMatch = data.match(/Registrar:\s*(.+)/i);
            if (registrarMatch) {
                resolve(registrarMatch[1].trim());
            } else {
                resolve('No registrar information found.');
            }
        });
    });
}

async function getEmailProvider(domain) {
    let mxRecords = [];
    let mxRecordNames = [];
    let primaryProvider = null;
    let possibleProviders = new Set();
    let spfRecord = null;
    let dmarcRecord = null;

    try {
        // Attempt to fetch MX records
        mxRecords = await dns.resolveMx(domain);
        mxRecordNames = mxRecords.map(record => record.exchange.toLowerCase());
    } catch (error) {
        if (error.code === 'ENODATA') {
            console.warn(`No MX records found for domain: ${domain}`);
            mxRecordNames = [];
        } else {
            console.error('Error fetching MX records:', error);
            return { error: `Error fetching MX records: ${error.message}` };
        }
    }

    // Process email provider based on MX records
    for (const { pattern, name, aliases = [] } of emailProviders) {
        const patterns = [pattern, ...aliases].map(p => p.toLowerCase());
        
        // Check if MX record strictly matches one of the provider's patterns or aliases
        if (patterns.some(p => mxRecordNames.some(record => record === p || record.endsWith(`.${p}`)))) {
            if (!primaryProvider) primaryProvider = name;
            possibleProviders.add(name);
            break;  // Stop checking once primary provider is found
        }
    }

    // Fetch SPF record
    try {
        const txtRecords = await dns.resolveTxt(domain);
        txtRecords.forEach((record) => {
            const joinedRecord = record.join('');
            if (joinedRecord.startsWith('v=spf1')) {
                spfRecord = joinedRecord;
            }
        });
    } catch (error) {
        if (error.code === 'ENODATA') {
            spfRecord = 'No SPF record found for this domain.';
        } else {
            console.error('Error fetching SPF record:', error);
            spfRecord = 'Error fetching SPF record.';
        }
    }

    // Fetch DMARC record
    try {
        const dmarcTxtRecords = await dns.resolveTxt(`_dmarc.${domain}`);
        dmarcTxtRecords.forEach((record) => {
            const joinedRecord = record.join('');
            if (joinedRecord.startsWith('v=DMARC1')) {
                dmarcRecord = joinedRecord;
            }
        });
    } catch (error) {
        if (error.code === 'ENODATA') {
            dmarcRecord = 'No DMARC record found for this domain.';
        } else {
            console.log('Error fetching DMARC record:', error);
            dmarcRecord = 'Error fetching DMARC record.';
        }
    }

    return {
        primaryProvider: primaryProvider || 'Email service provider unavailable',
        possibleProviders: Array.from(possibleProviders),
        mxRecords: mxRecordNames,
        spfRecord: spfRecord || 'SPF record not found',
        dmarcRecord: dmarcRecord || 'DMARC record not found'
    };
}

const hostingProvidersMap = {
    'awsdns': 'Amazon Web Services (AWS)',
    'cloudflare': 'Cloudflare',
    'digitalocean': 'DigitalOcean',
    'domaincontrol': 'GoDaddy',
    'google': 'Google Cloud DNS',
    'bluehost': 'Bluehost',
    'hostgator': 'HostGator',
    'linode': 'Linode',
    'namesilo': 'NameSilo',
    'registrar-servers': 'Namecheap',
    'rackspace': 'Rackspace',
    'dreamhost': 'DreamHost',
    'cloudns': 'ClouDNS',
    'gandi': 'Gandi.net',
    'hover': 'Hover',
    'ovh': 'OVH',
    '1and1': '1&1 IONOS',
    'inetdns': 'InetDNS',
    'domaindiscover': 'DomainDiscover',
    'register.com': 'Register.com',
    'a2hosting': 'A2 Hosting',
    'eurodns': 'EuroDNS',
    'zoho': 'Zoho DNS',
    'tucows': 'Tucows',
    'redbubble': 'Redbubble',
    'porkbun': 'Porkbun',
    'secureserver': 'GoDaddy Secured Server',
    'neustar': 'Neustar',
    'easyname': 'Easyname',
    'freenom': 'Freenom',
    'fivver': 'Fiverr',
    'dnsimple': 'DNSimple',
    'dnsmadeeasy': 'DNS Made Easy',
    'mydnsjp': 'MyDNS.JP',
    'openprovider': 'Openprovider',
    'namesco': 'Namesco',
    'serverion': 'Serverion',
    'webhostingtalk': 'WebHostingTalk',
    'hostinger': 'Hostinger',
    'he.net': 'Hurricane Electric',
    'vultr': 'Vultr',
    'dnshosting': 'DNS Hosting',
    'inwx': 'INWX',
    'zonomi': 'Zonomi',
    'mydomain': 'MyDomain',
    'sslwireless': 'SSL Wireless',
    'uk2.net': 'UK2',
    'fastdns': 'FastDNS',
    'easyDNS': 'easyDNS',
    'dathorn': 'Dathorn',
    'nexcess': 'Nexcess',
    'name.com': 'Name.com',
    'webcentral': 'WebCentral',
    'domaintools': 'DomainTools',
    'flaunt': 'Flaunt',
    'enom': 'eNom',
    'dnspark': 'DNS Park',
    'ns.cloudflare.com': 'Cloudflare',
    'whmcs': 'WHMCS',
    'luxhosting': 'LuxHosting',
    'keysystems': 'Key-Systems',
    'domainz': 'Domainz',
    'euroweb': 'Euroweb',
    'interserver': 'InterServer',
    'lastpass': 'LastPass',
    'westhost': 'WestHost',
    'iwantmyname': 'I Want My Name',
    'canadianwebhosting': 'Canadian Web Hosting',
    'netregistry': 'Netregistry',
    'uniregistry': 'Uniregistry',
    'dns4me': 'DNS4Me',
    'nameroot': 'NameRoot',
    'wixdns': 'Wix.com',
    'dongee': 'Dongee',
    'fwdcdn': 'Forward CDN',
    'accenture': 'Accenture',
    'amzndns': 'Amazon Route 53',

    'ns1.com': 'NS1',  // Updated mapping
};

function fetchHostingProvider(nameServer) {
    const ns = nameServer.toLowerCase();
    
    // First, check for exact matches
    if (hostingProvidersMap[ns]) {
        return hostingProvidersMap[ns];
    }
    
    // Then check for partial matches if no exact match is found
    for (const key in hostingProvidersMap) {
        if (ns.includes(key)) {
            return hostingProvidersMap[key];
        }
    }
    
    return 'Unknown Provider';
}



// Start the server
//app.listen(PORT, () => {
  //  console.log(`Server running on port ${PORT}`);
//});

// Start the server
module.exports = app;
