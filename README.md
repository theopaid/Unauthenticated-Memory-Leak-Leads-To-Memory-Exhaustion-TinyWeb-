# Security Advisory: Unauthenticated Memory Leak Leads To Memory Exhaustion (TinyWeb)

**Assigned CVE ID:** CVE-2026-67183

## Summary

TinyWeb allocates several objects while parsing each request and never frees them. The request and header structures have no destructors, and nothing deletes them after the response is sent. Worker memory grows with every request and never drops, so a steady stream of ordinary requests drives the worker out of memory.

## Affected software

- Project: TinyWeb (https://github.com/GeneralSandman/TinyWeb)
- Version reported by the build: `TnyWeb/0.0.8`
- Affected commits: `e48f15d` (2018-11-20), where these structures and the parser were introduced, through `a381da2` (2023-11-22, latest on `master`).
- Fixed version: none.

## Classification

- CWE-401: Missing Release of Memory after Effective Lifetime
- CVSS 4.0 base score: 8.7 (High)
- Vector: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

## Threat model

An unauthenticated remote attacker who can reach the server's listening TCP port (9090 in the shipped configuration) and send requests at a modest sustained rate. No credentials or user interaction are required. The requests can be well formed; no special payload is needed.

## Technical details

For each request, `HttpParser::execute()` allocates a `Url`, an `HttpHeaders`, and one `HttpHeader` per header line:

```cpp
// src/tiny_http/http_parser.cc:1692
request->url = new Url;

// src/tiny_http/http_parser.cc:1709
request->headers = new HttpHeaders;

// src/tiny_http/http_parser.cc:1033-1040
HttpHeader* header = new HttpHeader;
return_val = parseHeader(stream, offset, len, header);
...
result->generals.push_back(header);   // stored in a raw-pointer list
```

`HttpRequest` and `HttpHeaders` are plain structs with no destructor, so destroying an `HttpRequest` frees none of these:

```cpp
// src/tiny_http/http_parser.h:442
typedef struct HttpRequest {
    ...
    Url* url;
    HttpHeaders* headers;
    HttpBody* body;
} HttpRequest;

// src/tiny_http/http_parser.h:279-304
typedef struct HttpHeaders {
    ...
    std::list<HttpHeader*> generals;   // raw pointers, never deleted
    ...
} HttpHeaders;
```

`WebProtocol` holds the request in a `std::shared_ptr<HttpRequest>` (`src/tiny_http/http_protocol.h:49`). When the next request replaces it, the default `~HttpRequest` runs and leaks `url`, `headers`, `body`, and every `HttpHeader` in `generals`. The only `delete request` in the code is in `getDataFromProxy()` (`src/tiny_http/http_protocol.cc:194`), a function the request path never calls. Per-request response buffers from the memory pool add to the growth.

## Proof of concept

1. Start the server with the shipped configuration (listening on port 9090). Note the process ID of a worker.

2. Record the worker's resident memory:

```
grep VmRSS /proc/<worker_pid>/status
```

3. Send a batch of ordinary requests:

```
for i in $(seq 1 2000); do
  curl -s -o /dev/null http://TARGET:9090/
done
```

4. Read `VmRSS` again. It has grown and does not fall afterward. A representative run:

```
VmRSS before:              3704 kB
after  500 requests:       4788 kB
after 1000 requests:      22068 kB
after 1500 requests:      41652 kB
after 2000 requests:      59956 kB
```

The growth is monotonic, roughly 20 to 28 kB per request, with no plateau. Repeating the batch continues the climb until the worker is killed for running out of memory.

## Impact

An unauthenticated attacker can exhaust a worker's memory with a sustained request stream and force an out-of-memory condition, denying service. Ordinary traffic also leaks over time, so the condition can occur without an attacker.

## Remediation

Give `HttpRequest` and `HttpHeaders` destructors that free `url`, `headers`, `body`, and every `HttpHeader` in `generals`, or hold them in smart pointers so they are released automatically. Also release the per-request memory-pool buffers once the response has been sent.
