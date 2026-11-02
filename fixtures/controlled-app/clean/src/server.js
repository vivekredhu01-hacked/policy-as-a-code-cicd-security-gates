const http = require("node:http");
const { applicationName } = require("./config");

const server = http.createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok", application: applicationName }));
    return;
  }

  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "not found" }));
});

server.listen(process.env.PORT || 3000, "127.0.0.1", () => {
  console.log(`listening on ${server.address().port}`);
});
