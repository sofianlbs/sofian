import { connect } from "cloudflare:sockets";

// Variables
const rootDomain = "pannely.workers.dev";
const serviceName = "jambu";
const apiKey = "7e2f6633ebeb862e50d9238a4";
const apiEmail = "paoan@gmail.com";
const accountID = "cc54feaa44bfa6bbb30f";
const zoneID = "825bc64f18bd3812096aec";
let isApiReady = false;
let prxIP = "";
let cachedPrxList = [];

// Constant
const horse = "dHJvamFu";
const flash = "dmxlc3M=";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";

const APP_DOMAIN = `${serviceName}.${rootDomain}`;
const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), "ss"];
const KV_PRX_URL = "https://raw.githubusercontent.com/jaka2m/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const PRX_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const BAD_WORDS_LIST = "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt";
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

const PROXY_PER_PAGE = 5;

async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
  if (!kvPrxUrl) {
    throw new Error("No URL Provided!");
  }

  const kvPrx = await fetch(kvPrxUrl);
  if (kvPrx.status == 200) {
    return await kvPrx.json();
  } else {
    return {};
  }
}

async function getPrxList(prxBankUrl = PRX_BANK_URL) {
  if (!prxBankUrl) {
    throw new Error("No URL Provided!");
  }

  const prxBank = await fetch(prxBankUrl);
  if (prxBank.status == 200) {
    const text = (await prxBank.text()) || "";

    const prxString = text.split("\n").filter(Boolean);
    cachedPrxList = prxString
      .map((entry) => {
        const [prxIP, prxPort, country, org] = entry.split(",");
        return {
          prxIP: prxIP || "Unknown",
          prxPort: prxPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }

  return cachedPrxList;
}

async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function generatePagination(totalItems, itemsPerPage, currentPage, request) {
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const urlBase = '/sub';
  
  let paginationHtml = '';
  const maxPagesToShow = 5;

  let startPage = Math.max(0, currentPage - Math.floor(maxPagesToShow / 2));
  let endPage = Math.min(totalPages, startPage + maxPagesToShow);
  
  if (endPage - startPage < maxPagesToShow) {
    startPage = Math.max(0, endPage - maxPagesToShow);
  }

  // Tombol "Prev"
  if (currentPage > 0) {
    const prevUrl = new URL(request.url);
    prevUrl.searchParams.set('page', currentPage - 1);
    paginationHtml += `<a href="${prevUrl.pathname}${prevUrl.search}">Prev</a>`;
  }
  
  // Tombol Halaman
  for (let i = startPage; i < endPage; i++) {
    const pageNumber = i + 1;
    const activeClass = i === currentPage ? 'active' : '';
    const pageUrl = new URL(request.url);
    pageUrl.searchParams.set('page', i);
    paginationHtml += `<a href="${pageUrl.pathname}${pageUrl.search}" class="${activeClass}">${pageNumber}</a>`;
  }

  // Tombol "Next"
  if (currentPage < totalPages - 1) {
    const nextUrl = new URL(request.url);
    nextUrl.searchParams.set('page', currentPage + 1);
    paginationHtml += `<a href="${nextUrl.pathname}${nextUrl.search}">Next</a>`;
  }

  return paginationHtml;
}


function getAllConfig(request, hostName, proxyList, page = 0) {
  const totalProxies = proxyList.length;
  const startIndex = page * PROXY_PER_PAGE;
  const endIndex = Math.min(startIndex + PROXY_PER_PAGE, totalProxies);
  const paginatedProxyList = proxyList.slice(startIndex, endIndex);

  const fillerDomain = APP_DOMAIN;

  const htmlContent = `
    <!DOCTYPE html>
    <html lang="id">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Konfigurasi Proxy Nautica</title>
      <style>
        body { font-family: 'Poppins', sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 20px; }
        .config-list { display: flex; flex-direction: column; gap: 15px; }
        .config-item { background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; display: flex; flex-direction: column; position: relative; }
        .config-item h3 { margin: 0 0 10px 0; font-size: 16px; font-weight: 600; color: #555; }
        .config-url { font-size: 14px; color: #007bff; word-break: break-all; margin-bottom: 10px; }
        .copy-btn { 
          background-color: #28a745; 
          color: white; 
          border: none; 
          padding: 8px 12px; 
          border-radius: 4px; 
          cursor: pointer; 
          transition: background-color 0.3s ease;
          align-self: flex-start;
        }
        .copy-btn:hover { background-color: #218838; }
        .copy-btn:active { background-color: #1e7e34; }
        .pagination { display: flex; justify-content: center; align-items: center; margin-top: 20px; gap: 8px; }
        .pagination a, .pagination span { padding: 8px 12px; text-decoration: none; color: #007bff; border: 1px solid #007bff; border-radius: 4px; transition: all 0.2s; }
        .pagination a:hover { background-color: #e9ecef; }
        .pagination .active { background-color: #007bff; color: white; border-color: #007bff; }
        .info { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
      </style>
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Daftar Konfigurasi Proxy</h1>
          <p>Pilih dan salin konfigurasi yang Anda butuhkan.</p>
        </div>
        <div class="config-list">
          ${paginatedProxyList.map((prx, index) => {
            const baseId = startIndex + index;
            const uuid = crypto.randomUUID();
            
            // Konfigurasi VLESS, Trojan, SS untuk port 443 (TLS)
            const vlessUrlTls = new URL(`${atob(flash)}://${fillerDomain}`);
            vlessUrlTls.searchParams.set("encryption", "none");
            vlessUrlTls.searchParams.set("type", "ws");
            vlessUrlTls.searchParams.set("host", APP_DOMAIN);
            vlessUrlTls.username = uuid;
            vlessUrlTls.port = "443";
            vlessUrlTls.searchParams.set("security", "tls");
            vlessUrlTls.searchParams.set("sni", APP_DOMAIN);
            vlessUrlTls.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
            vlessUrlTls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} VLESS/WS/TLS [${serviceName}]`;

            const trojanUrlTls = new URL(`${atob(horse)}://${fillerDomain}`);
            trojanUrlTls.searchParams.set("encryption", "none");
            trojanUrlTls.searchParams.set("type", "ws");
            trojanUrlTls.searchParams.set("host", APP_DOMAIN);
            trojanUrlTls.username = uuid;
            trojanUrlTls.port = "443";
            trojanUrlTls.searchParams.set("security", "tls");
            trojanUrlTls.searchParams.set("sni", APP_DOMAIN);
            trojanUrlTls.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
            trojanUrlTls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} Trojan/WS/TLS [${serviceName}]`;

            const ssUrlTls = new URL(`ss://${fillerDomain}`);
            ssUrlTls.username = btoa(`none:${uuid}`);
            ssUrlTls.searchParams.set("plugin", `${atob(v2)}-plugin;tls;mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`);
            ssUrlTls.port = "443";
            ssUrlTls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} Shadowsocks/WS/TLS [${serviceName}]`;
            
            // Konfigurasi VLESS, Trojan, SS untuk port 80 (NTLS)
            const vlessUrlNtls = new URL(`${atob(flash)}://${fillerDomain}`);
            vlessUrlNtls.searchParams.set("encryption", "none");
            vlessUrlNtls.searchParams.set("type", "ws");
            vlessUrlNtls.searchParams.set("host", APP_DOMAIN);
            vlessUrlNtls.username = uuid;
            vlessUrlNtls.port = "80";
            vlessUrlNtls.searchParams.set("security", "none");
            vlessUrlNtls.searchParams.set("sni", ""); // SNI dikosongkan untuk NTLS
            vlessUrlNtls.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
            vlessUrlNtls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} VLESS/WS/NTLS [${serviceName}]`;

            const trojanUrlNtls = new URL(`${atob(horse)}://${fillerDomain}`);
            trojanUrlNtls.searchParams.set("encryption", "none");
            trojanUrlNtls.searchParams.set("type", "ws");
            trojanUrlNtls.searchParams.set("host", APP_DOMAIN);
            trojanUrlNtls.username = uuid;
            trojanUrlNtls.port = "80";
            trojanUrlNtls.searchParams.set("security", "none");
            trojanUrlNtls.searchParams.set("sni", "");
            trojanUrlNtls.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
            trojanUrlNtls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} Trojan/WS/NTLS [${serviceName}]`;

            const ssUrlNtls = new URL(`ss://${fillerDomain}`);
            ssUrlNtls.username = btoa(`none:${uuid}`);
            ssUrlNtls.searchParams.set("plugin", `${atob(v2)}-plugin;mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`);
            ssUrlNtls.port = "80";
            ssUrlNtls.hash = `${baseId + 1} ${getFlagEmoji(prx.country)} ${prx.org} Shadowsocks/WS/NTLS [${serviceName}]`;

            return `
              <div class="config-item">
                <h3>${getFlagEmoji(prx.country)} ${prx.org}</h3>
                <div class="config-details">
                  <p><strong>VLESS (TLS):</strong></p>
                  <div class="config-url" id="vless-tls-${baseId}">${vlessUrlTls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('vless-tls-${baseId}')">Copy VLESS TLS</button>

                  <p><strong>VLESS (NTLS):</strong></p>
                  <div class="config-url" id="vless-ntls-${baseId}">${vlessUrlNtls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('vless-ntls-${baseId}')">Copy VLESS NTLS</button>

                  <p><strong>Trojan (TLS):</strong></p>
                  <div class="config-url" id="trojan-tls-${baseId}">${trojanUrlTls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('trojan-tls-${baseId}')">Copy Trojan TLS</button>

                  <p><strong>Trojan (NTLS):</strong></p>
                  <div class="config-url" id="trojan-ntls-${baseId}">${trojanUrlNtls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('trojan-ntls-${baseId}')">Copy Trojan NTLS</button>

                  <p><strong>Shadowsocks (TLS):</strong></p>
                  <div class="config-url" id="ss-tls-${baseId}">${ssUrlTls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('ss-tls-${baseId}')">Copy SS TLS</button>

                  <p><strong>Shadowsocks (NTLS):</strong></p>
                  <div class="config-url" id="ss-ntls-${baseId}">${ssUrlNtls.toString()}</div>
                  <button class="copy-btn" onclick="copyConfig('ss-ntls-${baseId}')">Copy SS NTLS</button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
        <div class="pagination">
          ${generatePagination(totalProxies, PROXY_PER_PAGE, page, request)}
        </div>
        <div class="info">
          Menampilkan ${paginatedProxyList.length} dari ${totalProxies} konfigurasi.
        </div>
      </div>
      <script>
        function copyConfig(id) {
          const configElement = document.getElementById(id);
          const textToCopy = configElement.innerText;
          navigator.clipboard.writeText(textToCopy).then(() => {
            alert('Konfigurasi berhasil disalin!');
          }).catch(err => {
            console.error('Gagal menyalin: ', err);
            alert('Gagal menyalin konfigurasi.');
          });
        }
      </script>
    </body>
    </html>
  `;
    
  return new Response(htmlContent, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      if (apiKey && apiEmail && accountID && zoneID) {
        isApiReady = true;
      }

      if (upgradeHeader === "websocket") {
        const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          const kvPrx = await getKVPrxList();

          prxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];

          return await websocketHandler(request);
        } else if (prxMatch) {
          prxIP = prxMatch[1];
          return await websocketHandler(request);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        const page = parseInt(url.searchParams.get("page") || "0");
        const hostname = request.headers.get("Host");

        const countrySelectRaw = url.searchParams.get("cc")?.split(",");
        let countrySelect = [];

        if (countrySelectRaw) {
          countrySelect = countrySelectRaw.map(cc => {
            const normalizedCc = cc.toLowerCase().trim();
            const countryCodeMap = {};
            return countryCodeMap[normalizedCc] || cc.toUpperCase().trim();
          });
        }
        
        const prxBank = url.searchParams.get("proxy-list") || PRX_BANK_URL;
        let proxyList = (await getPrxList(prxBank)).filter((proxy) => {
          if (countrySelect.length > 0) {
            return countrySelect.includes(proxy.country);
          }
          return true;
        });
        
        return getAllConfig(request, hostname, proxyList, page);
      } else if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await checkProxyHealth(target[0], target[1] || "443");

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            ...CORS_HEADER_OPTIONS,
            "Content-Type": "application/json",
          },
        });
      } else if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (apiPath.startsWith("/domains")) {
          if (!isApiReady) {
            return new Response("Api not ready", {
              status: 500,
            });
          }

          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);

            return new Response(register.toString(), {
              status: register,
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          }
        } else if (apiPath.startsWith("/sub")) {
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

          const prxBankUrl = url.searchParams.get("prx-list") || PRX_BANK_URL;
          const prxList = await getPrxList(prxBankUrl)
            .then((prxs) => {
              if (filterCC.length) {
                return prxs.filter((prx) => filterCC.includes(prx.country));
              }
              return prxs;
            })
            .then((prxs) => {
              shuffleArray(prxs);
              return prxs;
            });

          const uuid = crypto.randomUUID();
          const result = [];
          for (const prx of prxList) {
            for (const port of filterPort) {
              for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;

                const uri = new URL(`${protocol}://${fillerDomain}`);
                uri.port = port.toString();
                
                if (protocol == atob(flash)) { // VLESS
                  uri.searchParams.set("encryption", "none");
                  uri.searchParams.set("type", "ws");
                  uri.searchParams.set("host", APP_DOMAIN);
                  uri.username = uuid;
                  uri.searchParams.set("security", port == 443 ? "tls" : "none");
                  uri.searchParams.set("sni", port == 443 ? APP_DOMAIN : "");
                  uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
                  uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} VLESS/WS/${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
                } else if (protocol == atob(horse)) { // Trojan
                  uri.searchParams.set("encryption", "none");
                  uri.searchParams.set("type", "ws");
                  uri.searchParams.set("host", APP_DOMAIN);
                  uri.username = uuid;
                  uri.searchParams.set("security", port == 443 ? "tls" : "none");
                  uri.searchParams.set("sni", port == 443 ? APP_DOMAIN : "");
                  uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
                  uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} Trojan/WS/${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
                } else if (protocol == "ss") { // Shadowsocks
                  uri.username = btoa(`none:${uuid}`);
                  uri.searchParams.set(
                    "plugin",
                    `${atob(v2)}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`
                  );
                  uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} Shadowsocks/WS/${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
                }

                result.push(uri.toString());
              }
            }
          }
          
          let finalResult = "";
          switch (filterFormat) {
            case "raw":
              finalResult = result.join("\n");
              break;
            case atob(v2):
              finalResult = btoa(result.join("\n"));
              break;
            case atob(neko):
            case "sfa":
            case "bfr":
              const res = await fetch(CONVERTER_URL, {
                method: "POST",
                body: JSON.stringify({
                  url: result.join(","),
                  format: filterFormat,
                  template: "cf",
                }),
              });
              if (res.status == 200) {
                finalResult = await res.text();
              } else {
                return new Response(res.statusText, {
                  status: res.status,
                  headers: {
                    ...CORS_HEADER_OPTIONS,
                  },
                });
              }
              break;
          }

          return new Response(finalResult, {
            status: 200,
            headers: {
              ...CORS_HEADER_OPTIONS,
            },
          });
        } else if (apiPath.startsWith("/myip")) {
          return new Response(
            JSON.stringify({
              ip:
                request.headers.get("cf-connecting-ipv6") ||
                request.headers.get("cf-connecting-ip") ||
                request.headers.get("x-real-ip"),
              colo: request.headers.get("cf-ray")?.split("-")[1],
              ...request.cf,
            }),
            {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            }
          );
        }
      }

      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      return await reverseWeb(request, targetReversePrx);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: {
          ...CORS_HEADER_OPTIONS,
        },
      });
    }
  },
};

async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              protocolHeader.version,
              log
            );
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss";
}

async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      prxIP.split(/[:=-]/)[0] || addressRemote,
      prxIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });

    log(`Connected to ${targetAddress}:${targetPort}`);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection to ${targetPort} aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound, error ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for SS: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not supported`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid request data",
    };
  }

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: dataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkPrxHealth(prxIP, prxPort) {
  const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
  return await req.json();
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let currentIndex = array.length;

  while (currentIndex != 0) {
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}

function reverse(s) {
  return s.split("").reverse().join("");
}

function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${apiKey}`;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.apiKey = apiKey;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
    };
  }

  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();

      return respJson.result.filter((data) => data.service == serviceName).map((data) => data.hostname);
    }

    return [];
  }

  async registerDomain(domain) {
    domain = domain.toLowerCase();
    const registeredDomains = await this.getDomainList();

    if (!domain.endsWith(rootDomain)) return 400;
    if (registeredDomains.includes(domain)) return 409;

    try {
      const domainTest = await fetch(`https://${domain.replaceAll("." + APP_DOMAIN, "")}`);
      if (domainTest.status == 530) return domainTest.status;

      const badWordsListRes = await fetch(BAD_WORDS_LIST);
      if (badWordsListRes.status == 200) {
        const badWordsList = (await badWordsListRes.text()).split("\n");
        for (const badWord of badWordsList) {
          if (domain.includes(badWord.toLowerCase())) {
            return 403;
          }
        }
      } else {
        return 403;
      }
    } catch (e) {
      return 400;
    }

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({
        environment: "production",
        hostname: domain,
        service: serviceName,
        zone_id: this.zoneID,
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
}
