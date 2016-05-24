##Simple WebSocket server using Boost ASIO Library.

* Supports concurrent web browser clients.
* Properly handles the WebSocket handshake to establish a tcp connection from a client web browser.
* Unmasks the received data and displays it on the console.
* The project includes (in the Client folder) a simple html webpage which opens a connection to the server and allows the user to send custom messages.

To run the server: http_server <address> <port> <doc_root>
For example: "http_server 0.0.0.0 5555 ."