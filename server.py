import asyncio, json, os, hashlib, time, socket
from typing import Dict, List

HOST = '0.0.0.0'
PORT = 12345
USERS_FILE = 'users.json'
MESSAGES_FILE = 'messages.json'
MAX_HISTORY = 1000

users: Dict[str, dict] = {}
messages: List[dict] = []
clients: List[dict] = []
tokens: Dict[str, dict] = {}

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(default, f, ensure_ascii=False)
        return default
    with open(path, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def make_token(username: str) -> str:
    return hashlib.sha256(f'{username}-{time.time()}'.encode('utf-8')).hexdigest()

users = load_json(USERS_FILE, {})
messages = load_json(MESSAGES_FILE, [])

def pack(obj):
    return (json.dumps(obj, ensure_ascii=False) + '\n').encode('utf-8')

async def send_writer(writer: asyncio.StreamWriter, obj):
    try:
        writer.write(pack(obj))
        await writer.drain()
    except Exception:
        pass

async def broadcast(obj, exclude_writer=None):
    data = pack(obj)
    remove = []
    for c in clients:
        w = c['writer']
        if exclude_writer is not None and w is exclude_writer:
            continue
        try:
            w.write(data)
            await w.drain()
        except Exception:
            remove.append(c)
    for c in remove:
        try:
            c['writer'].close()
            await c['writer'].wait_closed()
        except:
            pass
        if c in clients:
            clients.remove(c)

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    meta = {'addr': addr, 'username': None, 'display_name': None, 'token': None}
    print(f'[SERVER] Nova conexão {addr}')
    sock = writer.get_extra_info('socket')
    if sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
            except Exception:
                pass
        except Exception:
            pass

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                s = line.decode('utf-8').rstrip('\n')
            except Exception:
                await send_writer(writer, {'type':'error','message':'encoding error'})
                continue
            if not s:
                continue
            print(f'[SERVER] Recebido de {addr}: {s}')
            try:
                obj = json.loads(s)
            except Exception:
                await send_writer(writer, {'type':'error','message':'json inválido'})
                continue
            action = obj.get('action')

            if action == 'register':
                username = obj.get('username','').strip()
                password = obj.get('password','')
                if not username or not password:
                    await send_writer(writer, {'type':'error','message':'username/senha vazios'})
                    continue
                if username in users:
                    await send_writer(writer, {'type':'error','message':'username já existe'})
                else:
                    users[username] = {'password_hash': hash_password(password), 'created': time.time()}
                    save_json(USERS_FILE, users)
                    await send_writer(writer, {'type':'ok','action':'register','message':'registrado com sucesso'})

            elif action == 'login':
                username = obj.get('username','').strip()
                password = obj.get('password','')
                if not username or not password:
                    await send_writer(writer, {'type':'error','message':'username/senha vazios'})
                    continue
                if username not in users or users[username]['password_hash'] != hash_password(password):
                    await send_writer(writer, {'type':'error','message':'credenciais inválidas'})
                else:
                    token = make_token(username)
                    meta['username'] = username
                    meta['display_name'] = username
                    meta['token'] = token
                    tokens[token] = meta
                    clients.append({'writer': writer, 'meta': meta})
                    await send_writer(writer, {'type':'ok','action':'login','token':token,'display_name':username})
                    hist = messages[-MAX_HISTORY:]
                    await send_writer(writer, {'type':'history','messages':hist})
                    await broadcast({'type':'info','message':f'{username} entrou no chat.'}, exclude_writer=None)
                    print(f'[SERVER] Login OK {username} token {token}')

            elif action == 'set_name':
                token = obj.get('token')
                name = obj.get('name','').strip()
                m = tokens.get(token)
                if not m or m is not meta:
                    await send_writer(writer, {'type':'error','message':'não autenticado'})
                    continue
                meta['display_name'] = name or meta['username']
                await send_writer(writer, {'type':'ok','action':'set_name','display_name':meta['display_name']})
                await broadcast({'type':'info','message':f'{meta['username']} agora é {meta['display_name']}'})

            elif action == 'send':
                token = obj.get('token')
                text = obj.get('text','')
                m = tokens.get(token)
                if not m or m is not meta:
                    await send_writer(writer, {'type':'error','message':'token inválido ou não autenticado'})
                    continue
                if not text.strip():
                    continue
                ev = {'type':'message','from': meta['display_name'], 'text': text, 'timestamp': time.time()}
                messages.append(ev)
                if len(messages) > 500:
                    del messages[:-500]
                save_json(MESSAGES_FILE, messages)
                await broadcast(ev, exclude_writer=writer)
            else:
                await send_writer(writer, {'type':'error','message':'ação desconhecida'})

    except Exception as e:
        print(f'[SERVER] Erro conexão {addr}: {e}')
    finally:
        print(f'[SERVER] Conexão encerrada {addr}')
        for c in list(clients):
            if c['writer'] is writer:
                clients.remove(c)
        t = meta.get('token')
        if t and tokens.get(t) is meta:
            tokens.pop(t, None)
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass
        if meta.get('display_name'):
            await broadcast({'type':'info','message':f'{meta['display_name']} saiu do chat.'}, exclude_writer=None)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    local_ip = get_local_ip()
    print(f'[SERVER] Servidor asyncio rodando em {addr}')
    print(f'[SERVER] Endereço LAN/VPN: {local_ip}: {PORT}')
    print(f'[SERVER] Compartilhe esse IP com seus amigos para conectar-se.')
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('Servidor encerrado manualmente')
