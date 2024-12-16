// EDtunnel - A Cloudflare Worker-based VLESS Proxy with WebSocket Transport
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// ======================================
// Configuration
// ======================================

/**
 * User configuration and settings
 * Generate UUID: [Windows] Press "Win + R", input cmd and run: Powershell -NoExit -Command "[guid]::NewGuid()"
 */
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

/**
 * Array of proxy server addresses with ports
 * Format: ['hostname:port', 'hostname:port']
 */
const proxyIPs = ['35.219.15.90'];

// Randomly select a proxy server from the pool
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.includes(':') ? proxyIP.split(':')[1] : '443';

// Alternative configurations:
// Single proxy IP: let proxyIP = 'cdn.xn--b6gac.eu.org';
// IPv6 example: let proxyIP = "[2a01:4f8:c2c:123f:64:5:6810:c55a]"

/**
 * SOCKS5 proxy configuration
 * Format: 'username:password@host:port' or 'host:port'
 */
let socks5Address = '';

/**
 * SOCKS5 relay mode
 * When true: All traffic is proxied through SOCKS5
 * When false: Only Cloudflare IPs use SOCKS5
 */
let socks5Relay = false;

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

let parsedSocks5Address = {};
let enableSocks = false;

/**
 * Main handler for the Cloudflare Worker. Processes incoming requests and routes them appropriately.
 * @param {import("@cloudflare/workers-types").Request} request - The incoming request object
 * @param {Object} env - Environment variables containing configuration
 * @param {string} env.UUID - User ID for authentication
 * @param {string} env.PROXYIP - Proxy server IP address
 * @param {string} env.SOCKS5 - SOCKS5 proxy configuration
 * @param {string} env.SOCKS5_RELAY - SOCKS5 relay mode flag
 * @returns {Promise<Response>} Response object
 */
export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, SOCKS5: string, SOCKS5_RELAY: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} _ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, _ctx) {
		try {
			const { UUID, PROXYIP, SOCKS5, SOCKS5_RELAY } = env;
			userID = UUID || userID;
			socks5Address = SOCKS5 || socks5Address;
			socks5Relay = SOCKS5_RELAY || socks5Relay;

			// Handle proxy configuration
			const proxyConfig = handleProxyConfig(PROXYIP);
			proxyIP = proxyConfig.ip;
			proxyPort = proxyConfig.port;

			if (socks5Address) {
				try {
					const selectedSocks5 = selectRandomAddress(socks5Address);
					parsedSocks5Address = socks5AddressParser(selectedSocks5);
					enableSocks = true;
				} catch (err) {
					console.log(err.toString());
					enableSocks = false;
				}
			}

			const userIDs = userID.includes(',') ? userID.split(',').map(id => id.trim()) : [userID];
			const url = new URL(request.url);
			const host = request.headers.get('Host');
			const requestedPath = url.pathname.substring(1); // Remove leading slash
			const matchingUserID = userIDs.length === 1 ?
				(requestedPath === userIDs[0] || 
				 requestedPath === `sub/${userIDs[0]}` || 
				 requestedPath === `bestip/${userIDs[0]}` ? userIDs[0] : null) :
				userIDs.find(id => {
					const patterns = [id, `sub/${id}`, `bestip/${id}`];
					return patterns.some(pattern => requestedPath.startsWith(pattern));
				});

			if (request.headers.get('Upgrade') !== 'websocket') {
				if (url.pathname === '/cf') {
					return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: { "Content-Type": "application/json;charset=utf-8" },
					});
				}

				if (matchingUserID) {
					if (url.pathname === `/${matchingUserID}` || url.pathname === `/sub/${matchingUserID}`) {
						const isSubscription = url.pathname.startsWith('/sub/');
						const proxyAddresses = PROXYIP ? PROXYIP.split(',').map(addr => addr.trim()) : proxyIP;
						const content = isSubscription ?
							GenSub(matchingUserID, host, proxyAddresses) :
							getConfig(matchingUserID, host, proxyAddresses);

						return new Response(content, {
							status: 200,
							headers: {
								"Content-Type": isSubscription ?
									"text/plain;charset=utf-8" :
									"text/html; charset=utf-8"
							},
						});
					} else if (url.pathname === `/bestip/${matchingUserID}`) {
						return fetch(`https://sub.xf.free.hr/auto?host=${host}&uuid=${matchingUserID}&path=/`, { headers: request.headers });
					}
				}
				return handleDefaultPath(url, request);
			} else {
				return await ProtocolOverWSHandler(request);
			}
		} catch (err) {
			return new Response(err.toString());
		}
	},
};

/**
 * Handles default path requests when no specific route matches.
 * Generates and returns a cloud drive interface HTML page.
 * @param {URL} url - The URL object of the request
 * @param {Request} request - The incoming request object
 * @returns {Response} HTML response with cloud drive interface
 */
async function handleDefaultPath(url, request) {
	const host = request.headers.get('Host');
	const DrivePage = `
	  <!DOCTYPE html>
	  <html lang="en">
	  <head>
		  <meta charset="UTF-8">
		  <meta name="viewport" content="width=device-width, initial-scale=1.0">
		  <title>${host} - Cloud Drive</title>
		  <style>
			  body {
				  font-family: Arial, sans-serif;
				  line-height: 1.6;
				  margin: 0;
				  padding: 20px;
				  background-color: #f4f4f4;
			  }
			  .container {
				  max-width: 800px;
				  margin: auto;
				  background: white;
				  padding: 20px;
				  border-radius: 5px;
				  box-shadow: 0 0 10px rgba(0,0,0,0.1);
			  }
			  h1 {
				  color: #333;
			  }
			  .file-list {
				  list-style-type: none;
				  padding: 0;
			  }
			  .file-list li {
				  background: #f9f9f9;
				  margin-bottom: 10px;
				  padding: 10px;
				  border-radius: 3px;
				  display: flex;
				  align-items: center;
			  }
			  .file-list li:hover {
				  background: #f0f0f0;
			  }
			  .file-icon {
				  margin-right: 10px;
				  font-size: 1.2em;
			  }
			  .file-link {
				  text-decoration: none;
				  color: #0066cc;
				  flex-grow: 1;
			  }
			  .file-link:hover {
				  text-decoration: underline;
			  }
			  .upload-area {
				  margin-top: 20px;
				  padding: 40px;
				  background: #e9e9e9;
				  border: 2px dashed #aaa;
				  border-radius: 5px;
				  text-align: center;
				  cursor: pointer;
				  transition: all 0.3s ease;
			  }
			  .upload-area:hover, .upload-area.drag-over {
				  background: #d9d9d9;
				  border-color: #666;
			  }
			  .upload-area h2 {
				  margin-top: 0;
				  color: #333;
			  }
			  #fileInput {
				  display: none;
			  }
			  .upload-icon {
				  font-size: 48px;
				  color: #666;
				  margin-bottom: 10px;
			  }
			  .upload-text {
				  font-size: 18px;
				  color: #666;
			  }
			  .upload-status {
				  margin-top: 20px;
				  font-style: italic;
				  color: #666;
			  }
			  .file-actions {
				  display: flex;
				  gap: 10px;
			  }
			  .delete-btn {
				  color: #ff4444;
				  cursor: pointer;
				  background: none;
				  border: none;
				  padding: 5px;
			  }
			  .delete-btn:hover {
				  color: #ff0000;
			  }
			  .clear-all-btn {
				  background-color: #ff4444;
				  color: white;
				  border: none;
				  padding: 10px 15px;
				  border-radius: 4px;
				  cursor: pointer;
				  margin-bottom: 20px;
			  }
			  .clear-all-btn:hover {
				  background-color: #ff0000;
			  }
		  </style>
	  </head>
	  <body>
		  <div class="container">
			  <h1>Cloud Drive</h1>
			  <p>Welcome to your personal cloud storage. Here are your uploaded files:</p>
			  <button id="clearAllBtn" class="clear-all-btn">Clear All Files</button>
			  <ul id="fileList" class="file-list">
			  </ul>
			  <div id="uploadArea" class="upload-area">
				  <div class="upload-icon">📁</div>
				  <h2>Upload a File</h2>
				  <p class="upload-text">Drag and drop a file here or click to select</p>
				  <input type="file" id="fileInput" hidden>
			  </div>
			  <div id="uploadStatus" class="upload-status"></div>
		  </div>
		  <script>
			  function loadFileList() {
				  const fileList = document.getElementById('fileList');
				  const savedFiles = JSON.parse(localStorage.getItem('uploadedFiles')) || [];
				  fileList.innerHTML = '';
				  savedFiles.forEach((file, index) => {
					  const li = document.createElement('li');
					  li.innerHTML = \`
						  <span class="file-icon">📄</span>
						  <a href="https://ipfs.io/ipfs/\${file.Url.split('/').pop()}" class="file-link" target="_blank">\${file.Name}</a>
						  <div class="file-actions">
							  <button class="delete-btn" onclick="deleteFile(\${index})">
								  <span class="file-icon">❌</span>
							  </button>
						  </div>
					  \`;
					  fileList.appendChild(li);
				  });
			  }

			  function deleteFile(index) {
				  const savedFiles = JSON.parse(localStorage.getItem('uploadedFiles')) || [];
				  savedFiles.splice(index, 1);
				  localStorage.setItem('uploadedFiles', JSON.stringify(savedFiles));
				  loadFileList();
			  }

			  document.getElementById('clearAllBtn').addEventListener('click', () => {
				  if (confirm('Are you sure you want to clear all files?')) {
					  localStorage.removeItem('uploadedFiles');
					  loadFileList();
				  }
			  });

			  loadFileList();

			  const uploadArea = document.getElementById('uploadArea');
			  const fileInput = document.getElementById('fileInput');
			  const uploadStatus = document.getElementById('uploadStatus');

			  uploadArea.addEventListener('dragover', (e) => {
				  e.preventDefault();
				  uploadArea.classList.add('drag-over');
			  });

			  uploadArea.addEventListener('dragleave', () => {
				  uploadArea.classList.remove('drag-over');
			  });

			  uploadArea.addEventListener('drop', (e) => {
				  e.preventDefault();
				  uploadArea.classList.remove('drag-over');
				  const files = e.dataTransfer.files;
				  if (files.length) {
					  handleFileUpload(files[0]);
				  }
			  });

			  uploadArea.addEventListener('click', () => {
				  fileInput.click();
			  });

			  fileInput.addEventListener('change', (e) => {
				  const file = e.target.files[0];
				  if (file) {
					  handleFileUpload(file);
				  }
			  });

			  async function handleFileUpload(file) {
				  uploadStatus.textContent = \`Uploading: \${file.name}...\`;
				  
				  const formData = new FormData();
				  formData.append('file', file);

				  try {
					  const response = await fetch('https://app.img2ipfs.org/api/v0/add', {
						  method: 'POST',
						  body: formData,
						  headers: {
							  'Accept': 'application/json',
						  },
					  });

					  if (!response.ok) {
						  throw new Error('Upload failed');
					  }

					  const result = await response.json();
					  uploadStatus.textContent = \`File uploaded successfully! IPFS Hash: \${result.Hash}\`;
					  
					  const savedFiles = JSON.parse(localStorage.getItem('uploadedFiles')) || [];
					  savedFiles.push(result);
					  localStorage.setItem('uploadedFiles', JSON.stringify(savedFiles));
					  
					  loadFileList();
					  
				  } catch (error) {
					  console.error('Error:', error);
					  uploadStatus.textContent = 'Upload failed. Please try again.';
				  }
			  }
		  </script>
	  </body>
	  </html>
	`;

	// 返回伪装的网盘页面
	return new Response(DrivePage, {
		headers: {
			"content-type": "text/html;charset=UTF-8",
		},
	});
}

/**
 * Handles protocol over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the protocol header.
 * @param {import("@cloudflare/workers-types").Request} request - The incoming request object
 * @returns {Promise<Response>} WebSocket response
 */
async function ProtocolOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				ProtocolVersion = new Uint8Array([0, 0]),
				isUDP,
			} = ProcessProtocolHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
			}
			// Handle UDP connections for DNS (port 53) only
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy is only enabled for DNS (port 53)');
				}
				return; // Early return after setting isDns or throwing error
			}
			// ["version", "附加信息长度 N"]
			const ProtocolResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, ProtocolResponseHeader, log);
			}
			HandleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, ProtocolResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections for the proxy.
 * Establishes connection to remote server and manages data flow.
 * @param {Socket} remoteSocket - Remote socket connection
 * @param {string} addressType - Type of address (IPv4/IPv6)
 * @param {string} addressRemote - Remote server address
 * @param {number} portRemote - Remote server port
 * @param {Uint8Array} rawClientData - Raw data from client
 * @param {WebSocket} webSocket - WebSocket connection
 * @param {Uint8Array} protocolResponseHeader - Protocol response header
 * @param {Function} log - Logging function
 */
async function HandleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log,) {
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		let tcpSocket;
		if (socks5Relay) {
			tcpSocket = await socks5Connect(addressType, address, port, log)
		} else {
			tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
				: connect({
					hostname: address,
					port: port,
				});
		}
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // first write, normal is tls client hello
		writer.releaseLock();
		return tcpSocket;
	}

	// if the cf connect tcp socket have no incoming data, we retry to redirect ip
	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote, false);
		}
		// no matter retry success or not, close websocket
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
}

/**
 * Creates a readable stream from WebSocket server.
 * Handles early data and WebSocket messages.
 * @param {WebSocket} webSocketServer - WebSocket server instance
 * @param {string} earlyDataHeader - Header for early data (0-RTT)
 * @param {Function} log - Logging function
 * @returns {ReadableStream} Stream of WebSocket data
 */
function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(_controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

/**
 * Processes VLESS protocol header.
 * Extracts and validates protocol information from buffer.
 * @param {ArrayBuffer} protocolBuffer - Buffer containing protocol header
 * @param {string} userID - User ID for validation
 * @returns {Object} Processed header information
 */
function ProcessProtocolHeader(protocolBuffer, userID) {
	if (protocolBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data' };
	}

	const dataView = new DataView(protocolBuffer);
	const version = dataView.getUint8(0);
	const slicedBufferString = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));

	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	const isValidUser = uuids.some(uuid => slicedBufferString === uuid.trim()) ||
		(uuids.length === 1 && slicedBufferString === uuids[0].trim());

	console.log(`userID: ${slicedBufferString}`);

	if (!isValidUser) {
		return { hasError: true, message: 'invalid user' };
	}

	const optLength = dataView.getUint8(17);
	const command = dataView.getUint8(18 + optLength);

	if (command !== 1 && command !== 2) {
		return { hasError: true, message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux` };
	}

	const portIndex = 18 + optLength + 1;
	const portRemote = dataView.getUint16(portIndex);
	const addressType = dataView.getUint8(portIndex + 2);
	let addressValue, addressLength, addressValueIndex;

	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValueIndex = portIndex + 3;
			addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 2:
			addressLength = dataView.getUint8(portIndex + 3);
			addressValueIndex = portIndex + 4;
			addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3:
			addressLength = 16;
			addressValueIndex = portIndex + 3;
			addressValue = Array.from({ length: 8 }, (_, i) => dataVi
