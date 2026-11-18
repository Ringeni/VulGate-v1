"""Ordinary HTTP/1 and HTTP/2 peers for local functional regression only."""
import hashlib
import http.server
import socket
import socketserver
import threading
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, ResponseReceived, DataReceived, StreamEnded, StreamReset, ConnectionTerminated
from tools.postdeploy.http_process import HTTPWorker

TEXT = b'ordinary backend response\n'
HTML = b'<html><body>Hello<!--ordinary comment-->caf\xe9</body></html>'
RANGE = b'0123456789abcdef' * 256


class OrdinaryHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def do_GET(self):
        body = HTML if self.path.startswith('/html') else RANGE if self.path.startswith('/range') else TEXT
        status=200
        headers={}
        if self.path.startswith('/range') and self.headers.get('Range','').startswith('bytes='):
            first,last=self.headers['Range'][6:].split('-')
            start,end=int(first),min(int(last),len(body)-1)
            headers['Content-Range']=f'bytes {start}-{end}/{len(body)}'
            body=body[start:end+1]; status=206
        self.send_response(status)
        self.send_header('Content-Type','text/html; charset=ISO-8859-1' if self.path.startswith('/html') else 'text/plain')
        for key,value in headers.items(): self.send_header(key,value)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        self.do_GET()


class Peer(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        try:
            prefix=self.request.recv(24,socket.MSG_PEEK)
            if not prefix: return
            if not prefix.startswith(b'PRI * HTTP/2.0'):
                OrdinaryHTTP(self.request,self.client_address,self.server)
                return
            conn=H2Connection(config=H2Configuration(client_side=False,header_encoding='utf-8'))
            conn.initiate_connection(); self.request.sendall(conn.data_to_send())
            while True:
                raw=self.request.recv(65535)
                if not raw: break
                for event in conn.receive_data(raw):
                    if isinstance(event,RequestReceived):
                        conn.send_headers(event.stream_id,[(':status','200'),('content-type','text/plain'),
                            ('content-length',str(len(TEXT)))])
                        conn.send_data(event.stream_id,TEXT,end_stream=True)
                    elif isinstance(event,DataReceived):
                        conn.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
                self.request.sendall(conn.data_to_send())
        except (OSError,ValueError): pass


class Backend:
    def __enter__(self):
        self.server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Peer)
        self.server.daemon_threads=True
        self.port=self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        return self
    def __exit__(self,*args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)


class ServerWorker(HTTPWorker):
    def request(self,spec):
        if spec.get('protocol')!='h2': return super().request(spec)
        body=bytearray(); status=0; complete=False; reason=None
        try:
            with socket.create_connection(('127.0.0.1',self.port),timeout=5) as channel:
                conn=H2Connection(config=H2Configuration(client_side=True,header_encoding='utf-8'))
                conn.initiate_connection()
                conn.send_headers(1,[(':method','GET'),(':scheme','http'),(':authority','localhost'),
                    (':path',spec['path'])],end_stream=True)
                channel.sendall(conn.data_to_send())
                while not complete and reason is None:
                    data=channel.recv(65535)
                    if not data: reason='connection_closed'; break
                    for event in conn.receive_data(data):
                        if isinstance(event,ResponseReceived): status=int(dict(event.headers)[':status'])
                        elif isinstance(event,DataReceived):
                            body.extend(event.data); conn.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
                        elif isinstance(event,StreamEnded): complete=True
                        elif isinstance(event,(StreamReset,ConnectionTerminated)): reason=type(event).__name__
                    channel.sendall(conn.data_to_send())
        except OSError as error: reason=type(error).__name__
        return {'http_status':status,'response_complete':complete,'body_length':len(body),
                'body_text':body.decode('utf-8',errors='replace'),'body_sha256':hashlib.sha256(body).hexdigest(),
                'transport_error':reason}
