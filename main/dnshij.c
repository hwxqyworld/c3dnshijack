#include <string.h>
#include "driver/gpio.h"
// #include "gpio_ctrl.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/lwip_napt.h"

#define STA_SSID "50zxxx"
#define STA_PASS "wszxxx561"

#define AP_SSID  "big-yellow-ding-ding-car"
#define AP_PASS  "CarCarCar"

static esp_netif_t *ap_netif;

/* ---------------- 黑名单 ---------------- */
static const char *blacklist[] = {
    "zhkt.changyan.com",
    "example-block.com",
    NULL
};

static int is_blacklisted(const char *domain)
{
    for (int i = 0; blacklist[i]; i++) {
        if (strstr(domain, blacklist[i])) return 1;
    }
    return 0;
}

/* ---------------- HTTP 阻断页面 ---------------- */
/*
static void http_server_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) { vTaskDelete(NULL); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        vTaskDelete(NULL);
    }

    listen(sock, 5);

    const char *block_page =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body><h1>席清源大C哥最帅</h1></body></html>";

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) continue;

        char buf[512];
        recv(client, buf, sizeof(buf), 0);

        send(client, block_page, strlen(block_page), 0);
        close(client);
    }
}
*/
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

extern const unsigned char server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const unsigned char server_cert_pem_end[]   asm("_binary_server_cert_pem_end");
extern const unsigned char server_key_pem_start[]  asm("_binary_server_key_pem_start");
extern const unsigned char server_key_pem_end[]    asm("_binary_server_key_pem_end");

static void http_server_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) { vTaskDelete(NULL); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        vTaskDelete(NULL);
    }

    listen(sock, 5);

    const char *block_page =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body><h1>席清源大c哥最帅</h1></body></html>";

    // 初始化证书和密钥（共享）
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_ssl_config conf;

    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    mbedtls_ssl_config_init(&conf);

    mbedtls_x509_crt_parse(&cert,
        server_cert_pem_start,
        server_cert_pem_end - server_cert_pem_start);

    mbedtls_pk_parse_key(&key,
        server_key_pem_start,
        server_key_pem_end - server_key_pem_start,
        NULL, 0);

    mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_ca_chain(&conf, cert.next, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &cert, &key);

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) continue;

        // 为每个连接在堆上创建 SSL 上下文
        mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
        if (!ssl) {
            close(client);
            continue;
        }

        mbedtls_ssl_init(ssl);
        mbedtls_ssl_setup(ssl, &conf);
        mbedtls_ssl_set_bio(ssl, &client,
                            mbedtls_net_send, mbedtls_net_recv, NULL);

        if (mbedtls_ssl_handshake(ssl) == 0) {
            char buf[512];
            mbedtls_ssl_read(ssl, (unsigned char *)buf, sizeof(buf));
            mbedtls_ssl_write(ssl,
                (const unsigned char *)block_page,
                strlen(block_page));
        }

        mbedtls_ssl_close_notify(ssl);
        mbedtls_ssl_free(ssl);
        free(ssl);
        close(client);
    }
}


/* ---------------- 上游 DNS 查询 ---------------- */

static int dns_query_upstream(const uint8_t *req, int req_len,
                              uint8_t *resp, int *resp_len)
{
    const char *dns_servers[] = { "1.1.1.1", "8.8.8.8" };

    for (int i = 0; i < 2; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) continue;

        struct sockaddr_in dns = {0};
        dns.sin_family = AF_INET;
        dns.sin_port = htons(53);
        dns.sin_addr.s_addr = inet_addr(dns_servers[i]);

        sendto(sock, req, req_len, 0, (struct sockaddr *)&dns, sizeof(dns));

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in from;
        socklen_t len = sizeof(from);

        int n = recvfrom(sock, resp, 512, 0, (struct sockaddr *)&from, &len);
        close(sock);

        if (n > 0) {
            *resp_len = n;
            return 1;
        }
    }

    return 0;
}

/* ---------------- DNS 服务器 ---------------- */

static void dns_server_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { printf("DNS server error!"); vTaskDelete(NULL); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        vTaskDelete(NULL);
    }

    uint8_t buf[512];
    uint8_t resp[512];

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);

        int n = recvfrom(sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client, &len);
        if (n <= 0) continue;

        /* ---- 解析 QNAME ---- */
        char domain[256] = {0};
        int p = 12, d = 0;
        while (p < n && buf[p] != 0) {
            int len2 = buf[p++];
            for (int i = 0; i < len2; i++) domain[d++] = buf[p++];
            domain[d++] = '.';
        }
        domain[d - 1] = 0;
        p += 5;

        /* ---- 黑名单处理 ---- */
        if (is_blacklisted(domain)) {
            memcpy(resp, buf, n);
            resp[2] = 0x81; resp[3] = 0x80;
            resp[4] = 0x00; resp[5] = 0x01;
            resp[6] = 0x00; resp[7] = 0x01;

            int pos = p;

            resp[pos++] = 0xC0; resp[pos++] = 0x0C;
            resp[pos++] = 0x00; resp[pos++] = 0x01;
            resp[pos++] = 0x00; resp[pos++] = 0x01;
            resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x00; resp[pos++] = 0x3C;
            resp[pos++] = 0x00; resp[pos++] = 0x04;

            esp_netif_ip_info_t ip_info;
            esp_netif_get_ip_info(ap_netif, &ip_info);
            uint32_t ip = ip_info.ip.addr;
//            uint32_t ip = 0x6e2a2da9;

            resp[pos++] = ip & 0xFF;
            resp[pos++] = (ip >> 8) & 0xFF;
            resp[pos++] = (ip >> 16) & 0xFF;
            resp[pos++] = (ip >> 24) & 0xFF;

            sendto(sock, resp, pos, 0, (struct sockaddr *)&client, len);
            continue;
        }

        /* ---- 非黑名单：上游 DNS 查询 ---- */
        int resp_len = 0;
        if (dns_query_upstream(buf, n, resp, &resp_len)) {
            sendto(sock, resp, resp_len, 0, (struct sockaddr *)&client, len);
        }
    }
}

/* ---------------- NAT 启用 ---------------- */

static int nat_enabled = 0;
static int sta_enabled = 0;
static void enable_napt()
{
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(ap_netif, &ip_info);

    printf("Enable NAPT on AP: %s\n", ip4addr_ntoa((const ip4_addr_t *)&ip_info.ip));

    if (nat_enabled) {
        // ip_napt_enable(ip_info.ip.addr, 1);
    }
}

/* ---------------- AP 启动事件 ---------------- */

static void on_ap_start(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    printf("AP started, launching DNS/HTTP servers...\n");

    esp_netif_dhcps_stop(ap_netif);
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(ap_netif, &ip_info);

    esp_netif_dns_info_t dns;
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = ip_info.ip.addr;

    esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_DOMAIN_NAME_SERVER, &dns, sizeof(dns));

    esp_netif_dhcps_start(ap_netif);
    xTaskCreate(dns_server_task, "dns_server", 12880, NULL, 5, NULL);
    xTaskCreate(http_server_task, "http_server", 12880, NULL, 5, NULL);
}

/* ---------------- STA 获得 IP 事件 ---------------- */

static void on_sta_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    enable_napt();
}

/* ---------------- WiFi 初始化 ---------------- */

static void wifi_init(void)
{

    esp_netif_init();
    esp_event_loop_create_default();

    // gpio_ctrl_init();
    // sta_enabled = gpio_ctrl_sta_nat_enabled();
    sta_enabled = 0;
    nat_enabled = sta_enabled;

    ap_netif = esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .password = AP_PASS,
            .channel = 1,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    esp_wifi_set_mode(sta_enabled ? WIFI_MODE_APSTA : WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    if (sta_enabled) {
        wifi_config_t sta_cfg = {
            .sta = {
                .ssid = STA_SSID,
                .password = STA_PASS,
            },
        };
        esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    }

    /* 注册事件 */
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_START, &on_ap_start, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_sta_got_ip, NULL);
    esp_wifi_start();
    if (sta_enabled) {
        esp_wifi_connect();
    }

    /* DHCP 下发 DNS = AP 自己 */
/*  esp_netif_dhcps_stop(ap_netif);

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(ap_netif, &ip_info);

    esp_netif_dns_info_t dns;
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = ip_info.ip.addr;

    esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_DOMAIN_NAME_SERVER, &dns, sizeof(dns));

    esp_netif_dhcps_start(ap_netif);*/
}

/* ---------------- 主入口 ---------------- */

void app_main(void)
{
    nvs_flash_init();
    wifi_init();
}
