use chrono::{
    format::{DelayedFormat, StrftimeItems},
    prelude::Local,
    SecondsFormat,
};
use fakedata_generator::{gen_domain, gen_ipv4, gen_username};
use rand::{thread_rng, Rng};

static APPLICATION_NAMES: [&str; 10] = [
    "auth", "data", "deploy", "etl", "scraper", "cron", "ingress", "egress", "alerter", "fwd",
];

static ERROR_LEVELS: [&str; 9] = [
    "alert", "crit", "debug", "emerg", "error", "info", "notice", "trace1-8", "warn",
];

static HTTP_CODES: [usize; 15] = [
    200, 300, 301, 302, 304, 307, 400, 401, 403, 404, 410, 500, 501, 503, 550,
];

static HTTP_SSL_CIPHERS: [&str; 4] = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
];

static HTTP_VERSIONS: [&str; 3] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"];
static HTTP_METHODS: [&str; 7] = ["DELETE", "GET", "HEAD", "OPTION", "PATCH", "POST", "PUT"];

static HTTP_ENDPOINTS: [&str; 9] = [
    "/wp-admin",
    "/controller/setup",
    "/user/booperbot124",
    "/apps/deploy",
    "/observability/metrics/production",
    "/secret-info/open-sesame",
    "/booper/bopper/mooper/mopper",
    "/do-not-access/needs-work",
    "/this/endpoint/prints/money",
];

static HTTP_REQUESTS: [&str; 4] = [
    "https://10.0.0.30:443/",
    "http://www.example.com:80/",
    "http://10.0.0.30:80/",
    "http://www.example.com:443/",
];

static HTTP_USER_AGENTS: [&str; 5] = [
    "curl/7.46.0",
    "ELB-HealthChecker/2.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.65 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/43.4",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
];

static ERROR_MESSAGES: [&str; 9] = [
    "There's a breach in the warp core, captain",
    "Great Scott! We're never gonna reach 88 mph with the flux capacitor in its current state!",
    "You're not gonna believe what just happened",
    "#hugops to everyone who has to deal with this",
    "Take a breath, let it go, walk away",
    "A bug was encountered but not in Vector, which doesn't have bugs",
    "We're gonna need a bigger boat",
    "Maybe we just shouldn't use computers",
    "Pretty pretty pretty good",
];

// AWS

static AWS_ACCOUNTS: [&str; 4] = [
    "123456789012",
    "210987654321",
    "012357121931",
    "141592653589"
];

static AWS_REGIONS: [&str; 2] = [
    "us-east-1",
    "us-west-1",
];

// AWS ELB 
static AWS_ELBS: [&str; 4] = [
    "app/zaphod-loadbalancer/50dc6c495c0c9188",
    "app/ford-loadbalancer/8819c0c594c6cd05",
    "app/trillian-loadbalancer/0123456789abcdef",
    "app/marvin-loadbalancer/fedcba9876543210",
];

static AWS_ELB_ACTIONS: [&str; 8] = [
    "authenticate", "fixed-response", "forward", "redirect", "waf", "waf-failed", "waf,forward","waf,redirect"
];

static AWS_ELB_CERT_IDS: [&str; 1] = [
    "12345678-1234-1234-1234-123456789012",
];

static AWS_ELB_CLASSIFICATIONS: [&str; 1] = [
    "-"
];

static AWS_ELB_CLASSIFICATION_REASONS: [&str; 21] = [
    "-","AmbiguousUri", "Ambiguous", "BadContentLength", "BadHeader", "BadTransferEncoding", "BadUri", "BadMethod", "BadVersion", 
    "BothTeClPresent", "DuplicateContentLength", "EmptyHeader", "GetHeadZeroContentLength", "MultipleContentLength",
    "MultipleTransferEncodingChunked", "NonCompliantHeader", "NonCompliantVersion", "SpaceInUri", "SuspiciousHeader", 
    "UndefinedContentLengthSemantics", "UndefinedTransferEncodingSemantics",
];

static AWS_ELB_ERROR_REASONS: [&str; 1] = [
    "-"
];

static AWS_ELB_REDIRECT_URLS: [&str; 2] = [
    "-",
    "https://10.0.0.1:443/healthcheck"
];

static AWS_ELB_REQUEST_TYPES: [&str; 6] = [
    "http", "https", "h2", "grpcs", "ws", "wss", 
];

static AWS_ELB_TARGET_GROUP_ARNS: [&str; 1] = [
    "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067",
];

static AWS_ELB_TRACE_IDS: [&str; 3] = [
    "Root=1-58337262-36d228ad5d99923122bbe354",
    "Root=1-26273385-453ebb22132999d5da822d63",
    "Root=1-12345678-0123456789abcdef0a1b2c3d",
];

const APACHE_COMMON_TIME_FORMAT: &str = "%d/%b/%Y:%T %z";
const APACHE_ERROR_TIME_FORMAT: &str = "%a %b %d %T %Y";
const SYSLOG_3164_FORMAT: &str = "%b %d %T";
const JSON_TIME_FORMAT: &str = "%d/%b/%Y:%T";
const ISO_8601_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";


pub fn aws_elb_log_line() -> String {
    // Example log line:
    // http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 
    //   192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 
    //   "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - 
    //   arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067
    //   "Root=1-58337262-36d228ad5d99923122bbe354" "-" "-" 
    //   0 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"A
    let request_type = aws_elb_request_type();
    let aws_account_id = aws_account();
    let aws_region = aws_region();
    let mut a_elb_cert_arn: String  = "-".to_string();
    let mut h_ssl_cipher: &str   = "-";
    let mut h_ssl_protocol: &str = "-";

    if request_type == "https" ||
       request_type == "wss" {
        a_elb_cert_arn = aws_elb_cert_arn(aws_account_id,aws_region);
        h_ssl_cipher  = http_ssl_cipher();
        h_ssl_protocol = "TLSv1.2"; 
    };

    format!(
    "{} {} {} {}:{} {}:{} {} {} {} {} {} {} {} \"{} {} {}\" \"{}\" {} {} {} \"{}\" \"{}\" \"{}\" {} {} \"{}\" \"{}\" \"{}\" \"{}:{}\" \"{}\" \"{}\" \"{}\"",
        request_type,                       // type
        timestamp_iso_8601(),               // time
        aws_elb(),                          // elb
        ipv4_address(),                     // client
        port(),                             // client_port
        ipv4_address(),                     // target
        port(),                             // target_port
        random_in_range(1, 999),            // request_procesing_time
        random_in_range(1, 999),            // target_processing_time
        random_in_range(1, 999),            // response_processing_time
        http_code(),                        // elb_status_code
        http_code(),                        // target_status_code
        byte_size(),                        // received_bytes
        byte_size(),                        // sent_bytes
        http_method(),                      // request method
        http_request(),                     // request URL
        http_version(),                     // Request HTTP Version
        http_user_agent(),                  // "user_agent"
        h_ssl_cipher,                    // SSL Cipher
        h_ssl_protocol,                  // SSL protocol
        aws_elb_targetgroup_arn(),          // target_group_arn
        aws_elb_trace_id(),                 // "trace_id"
        domain(),                           // "domain_name"
        a_elb_cert_arn,                 // "chosen_cert_arn"
        random_in_range(1, 9),              // matched_rule_priority
        timestamp_iso_8601(),               // request_creation_time
        aws_elb_action(),                   // "action_executed"
        aws_elb_redirect_url(),             // "redirect_url"
        aws_elb_error_reason(),             // "error_reason"
        ipv4_address(),                     // target list
        port(),                             // target port list
        http_code(),                        // "target_status_code_list"
        aws_elb_classification(),           // "classification"
        aws_elb_classification_reason(),    // "clasicication_reason"
    )
}

pub fn apache_common_log_line() -> String {
    // Example log line:
    // 173.159.239.159 - schoen1464 [31/Oct/2020:19:06:10 -0700] "POST /wireless HTTP/2.0" 100 20815
    format!(
        "{} - {} [{}] \"{} {} {}\" {} {}",
        ipv4_address(),
        username(),
        timestamp_apache_common(),
        http_method(),
        http_endpoint(),
        http_version(),
        http_code(),
        byte_size(),
    )
}

pub fn apache_error_log_line() -> String {
    // Example log line:
    // [Sat Oct 31 19:27:55 2020] [deleniti:crit] [pid 879:tid 9607] [client 169.198.228.174:1364] Something bad happened
    format!(
        "[{}] [{}:{}] [pid {}:tid] [client {}:{}] {}",
        timestamp_apache_error(),
        username(),
        error_level(),
        pid(),
        ipv4_address(),
        port(),
        error_message(),
    )
}

pub fn syslog_3164_log_line() -> String {
    format!(
        "<{}>{} {} {}[{}]: {}",
        priority(),
        timestamp_syslog_3164(),
        domain(),
        application(),
        pid(),
        error_message()
    )
}

pub fn syslog_5424_log_line() -> String {
    // Example log line:
    // <65>2 2020-11-05T18:11:43.975Z chiefubiquitous.io totam 6899 ID44 - Something bad happened
    format!(
        "<{}>{} {} {} {} {} ID{} - {}",
        priority(),
        syslog_version(),
        timestamp_syslog_5424(),
        domain(),
        username(),
        random_in_range(100, 9999),
        random_in_range(1, 999),
        error_message(),
    )
}

pub fn json_log_line() -> String {
    // Borrowed from Flog: https://github.com/mingrammer/flog/blob/master/log.go#L24
    // Example log line:
    // {"host":"208.171.64.160", "user-identifier":"hoppe7055", "datetime":" -0800", "method": \
    //   "PATCH", "request": "/web+services/cross-media/strategize", "protocol":"HTTP/1.1", \
    //   "status":403, "bytes":25926, "referer": "https://www.leadworld-class.org/revolutionize/applications"}
    format!(
        "{{\"host\":\"{}\",\"user-identifier\":\"{}\",\"datetime\":\"{}\",\"method\":\"{}\",\"request\":\"{}\",\"protocol\":\"{}\",\"status\":\"{}\",\"bytes\":{},\"referer\":\"{}\"}}",
        ipv4_address(),
        username(),
        timestamp_json(),
        http_method(),
        http_endpoint(),
        http_version(),
        http_code(),
        random_in_range(1000, 50000),
        referer(),
    )
}

// Formatted timestamps
fn timestamp_apache_common() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format(APACHE_COMMON_TIME_FORMAT)
}

fn timestamp_apache_error() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format(APACHE_ERROR_TIME_FORMAT)
}

fn timestamp_syslog_3164() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format(SYSLOG_3164_FORMAT)
}

fn timestamp_syslog_5424() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn timestamp_json() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format(JSON_TIME_FORMAT)
}

fn timestamp_iso_8601() -> DelayedFormat<StrftimeItems<'static>> {
    Local::now().format(ISO_8601_TIME_FORMAT)
}

// AWS Functions
fn aws_account() -> &'static str{
    random_from_array(&AWS_ACCOUNTS)
}

// AWS ELB Functions
fn aws_elb_action() -> &'static str{
    random_from_array(&AWS_ELB_ACTIONS)
}

fn aws_elb() -> &'static str{
    random_from_array(&AWS_ELBS)
}

fn aws_elb_cert_arn(account_id: &str, region: &str) -> String{
    format!(
        "arn:aws:acm:{}:{}:certificate/{}",
            region,
            account_id,
            random_from_array(&AWS_ELB_CERT_IDS)

    )
}

fn aws_elb_classification() -> &'static str{
    random_from_array(&AWS_ELB_CLASSIFICATIONS)
}

fn aws_elb_classification_reason() -> &'static str{
    random_from_array(&AWS_ELB_CLASSIFICATION_REASONS)
}

fn aws_elb_error_reason() -> &'static str{
    random_from_array(&AWS_ELB_ERROR_REASONS)
}

fn aws_elb_request_type() -> &'static str{
    random_from_array(&AWS_ELB_REQUEST_TYPES)
}

fn aws_elb_redirect_url() -> &'static str{
    random_from_array(&AWS_ELB_REDIRECT_URLS)
}

fn aws_elb_targetgroup_arn() -> &'static str{
    random_from_array(&AWS_ELB_TARGET_GROUP_ARNS)
}

fn aws_elb_trace_id() -> &'static str{
    random_from_array(&AWS_ELB_TRACE_IDS)
}

fn aws_region() -> &'static str{
    random_from_array(&AWS_REGIONS)
}

// Other random strings
fn application() -> &'static str {
    random_from_array(&APPLICATION_NAMES)
}

fn domain() -> String {
    gen_domain()
}

fn error_level() -> &'static str {
    random_from_array(&ERROR_LEVELS)
}

fn error_message() -> &'static str {
    random_from_array(&ERROR_MESSAGES)
}

fn http_code() -> usize {
    random_from_array_copied(&HTTP_CODES)
}

fn byte_size() -> usize {
    random_in_range(50, 50000)
}

fn http_endpoint() -> &'static str {
    random_from_array(&HTTP_ENDPOINTS)
}

fn http_request() -> &'static str {
    random_from_array(&HTTP_REQUESTS)
}

fn http_user_agent() -> &'static str {
    random_from_array(&HTTP_USER_AGENTS)
}

fn http_method() -> &'static str {
    random_from_array(&HTTP_METHODS)
}

fn http_ssl_cipher() -> &'static str {
    random_from_array(&HTTP_SSL_CIPHERS)
}

fn http_version() -> &'static str {
    random_from_array(&HTTP_VERSIONS)
}

fn ipv4_address() -> String {
    gen_ipv4()
}

fn pid() -> usize {
    random_in_range(1, 9999)
}

fn port() -> usize {
    random_in_range(1024, 65535)
}

fn priority() -> usize {
    random_in_range(0, 191)
}

fn referer() -> String {
    format!("https://{}{}", domain(), http_endpoint())
}

fn username() -> String {
    gen_username()
}

fn syslog_version() -> usize {
    random_in_range(1, 3)
}

// Helper functions
fn random_in_range(min: usize, max: usize) -> usize {
    thread_rng().gen_range(min..max)
}

fn random_from_array<T: ?Sized>(v: &'static [&'static T]) -> &'static T {
    v[thread_rng().gen_range(0..v.len())]
}

fn random_from_array_copied<T: Copy>(v: &[T]) -> T {
    v[thread_rng().gen_range(0..v.len())]
}
