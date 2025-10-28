import socket, threading, json, queue, time
import customtkinter as ctk
from tkinter import messagebox, scrolledtext

HOST = 'SEU IP AQUI!!!'
PORT = 12345

messagebox.showerror(
    '⚠️ ATENÇÃO ⚠️',
    'Para utilizar o chat é necessário ter um VPN ativo.\n'
    'Após configurar o VPN, use o IP fornecido pelo "server.py" para conectar-se ao servidor!'
)

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title('💬 Chat - Cliente')
        master.geometry('700x600')
        master.resizable(False, False)

        ctk.set_appearance_mode("dark")  # "dark" ou "light"
        ctk.set_default_color_theme("blue")  # opções: blue, dark-blue, green

        self.sock = None
        self.rfile = None
        self.wfile = None
        self.listener_thread = None
        self.recv_queue = queue.Queue()
        self.token = None
        self.username = None
        self.display_name = None

        # === Login Frame ===
        top = ctk.CTkFrame(master)
        top.pack(padx=10, pady=8, fill='x')

        ctk.CTkLabel(top, text='Usuário:').grid(row=0, column=0, padx=4)
        self.ent_user = ctk.CTkEntry(top, width=140, placeholder_text="Digite seu usuário")
        self.ent_user.grid(row=0, column=1, padx=4)

        ctk.CTkLabel(top, text='Senha:').grid(row=0, column=2, padx=4)
        self.ent_pass = ctk.CTkEntry(top, width=140, placeholder_text="••••••", show='*')
        self.ent_pass.grid(row=0, column=3, padx=4)

        self.btn_register = ctk.CTkButton(top, text='Registrar', command=self.do_register)
        self.btn_register.grid(row=0, column=4, padx=6)

        self.btn_login = ctk.CTkButton(top, text='Login', fg_color='#1E90FF', command=self.do_login)
        self.btn_login.grid(row=0, column=5, padx=6)

        # === Apelido ===
        name_frame = ctk.CTkFrame(master)
        name_frame.pack(padx=10, pady=8, fill='x')

        ctk.CTkLabel(name_frame, text='Apelido:').pack(side='left', padx=4)
        self.ent_name = ctk.CTkEntry(name_frame, width=200, placeholder_text="Seu apelido")
        self.ent_name.pack(side='left', padx=6)
        self.btn_set_name = ctk.CTkButton(name_frame, text='Definir Apelido', command=self.do_set_name)
        self.btn_set_name.pack(side='left', padx=6)

        # === Área de mensagens ===
        self.txt_area = scrolledtext.ScrolledText(
            master, state='disabled', wrap='word',
            width=80, height=20, bg='#202020', fg='white', insertbackground='white'
        )
        self.txt_area.pack(padx=10, pady=10)

        self.txt_area.tag_config('sys', foreground='#888888')
        self.txt_area.tag_config('me', foreground='#1E90FF')
        self.txt_area.tag_config('user', foreground='#00C46B')
        self.txt_area.tag_config('time', foreground='#5C5C95')

        # === Envio de mensagem ===
        bottom = ctk.CTkFrame(master)
        bottom.pack(padx=10, pady=10, fill='x')

        self.ent_msg = ctk.CTkEntry(bottom, placeholder_text='Digite sua mensagem...')
        self.ent_msg.pack(side='left', expand=True, fill='x', padx=4)
        self.ent_msg.bind('<Return>', lambda e: self.do_send())

        self.btn_send = ctk.CTkButton(bottom, text='Enviar ✏️', fg_color='#2E8B57', command=self.do_send)
        self.btn_send.pack(side='left', padx=8)

        # === Status ===
        self.status = ctk.CTkLabel(master, text='Desconectado', anchor='w', text_color='#FF5555')
        self.status.pack(fill='x', padx=10, pady=(0,10))

        self.connect_to_server(HOST, PORT)
        self.master.after(100, self.process_incoming)

    # === Lógica de rede e mensagens ===
    def connect_to_server(self, host, port):
        try:
            self.sock = socket.create_connection((host, port))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 60)
            self.rfile = self.sock.makefile('r', encoding='utf-8', newline='\n')
            self.wfile = self.sock.makefile('w', encoding='utf-8', newline='\n')
            self.listener_thread = threading.Thread(target=self.listen_loop, daemon=True)
            self.listener_thread.start()
            self.set_status('Conectado ✅', color='#00FF7F')
        except Exception as e:
            messagebox.showerror('Erro', f'Não conseguiu conectar ao servidor: {e}')
            self.set_status('Desconectado ❌', color='#FF5555')

    def listen_loop(self):
        try:
            for line in self.rfile:
                if not line:
                    break
                obj = json.loads(line.strip())
                self.recv_queue.put(obj)
        except Exception as e:
            self.recv_queue.put({'type': 'info', 'message': f'Erro conexão: {e}'})
        finally:
            self.recv_queue.put({'type': 'info', 'message': 'Desconectado do servidor'})

    def process_incoming(self):
        while True:
            try:
                obj = self.recv_queue.get_nowait()
            except queue.Empty:
                break
            self.handle_server_obj(obj)
        self.master.after(100, self.process_incoming)

    def handle_server_obj(self, obj):
        t = obj.get('type')
        if t == 'message':
            ts = time.strftime('%H:%M:%S', time.localtime(obj.get('timestamp', time.time())))
            self.append_text(f'[{ts}] ', 'time')
            self.append_text(f'{obj.get("from")}: ', 'user')
            self.append_text(f'{obj.get("text")}\n')
        elif t == 'info':
            self.append_text(f'[info] {obj.get("message")}\n', 'sys')
        elif t == 'error':
            messagebox.showerror('Erro do servidor', obj.get('message'))
        elif t == 'ok':
            action = obj.get('action')
            if action == 'login':
                self.token = obj.get('token')
                self.display_name = obj.get('display_name')
                self.set_status(f'Logado: {self.display_name}', color='#00FF7F')
                self.append_text(f'[sistema] Logado como {self.display_name}\n', 'sys')
            elif action == 'register':
                messagebox.showinfo('Registro', obj.get('message'))
            elif action == 'set_name':
                self.display_name = obj.get('display_name')
                self.set_status(f'Apelido: {self.display_name}', color='#00FF7F')
                self.append_text(f'[sistema] Apelido atualizado: {self.display_name}\n', 'sys')
        elif t == 'history':
            msgs = obj.get('messages', [])
            if msgs:
                self.append_text('[sistema] Histórico:\n', 'sys')
                for m in msgs:
                    ts = time.strftime('%H:%M:%S', time.localtime(m.get('timestamp', time.time())))
                    self.append_text(f'[{ts}] ', 'time')
                    self.append_text(f'{m.get("from")}: ', 'user')
                    self.append_text(f'{m.get("text")}\n')

    def append_text(self, text, tag=None):
        self.txt_area.configure(state='normal')
        if tag:
            self.txt_area.insert('end', text, (tag,))
        else:
            self.txt_area.insert('end', text)
        self.txt_area.see('end')
        self.txt_area.configure(state='disabled')

    def send_json(self, obj):
        if not self.wfile:
            messagebox.showerror('Erro', 'Não conectado ao servidor')
            return
        try:
            self.wfile.write(json.dumps(obj, ensure_ascii=False) + '\n')
            self.wfile.flush()
        except Exception as e:
            messagebox.showerror('Erro', f'Falha ao enviar: {e}')

    def do_register(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u or not p:
            messagebox.showwarning('Aviso', 'Preencha usuário e senha')
            return
        self.send_json({'action':'register','username':u,'password':p})

    def do_login(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u or not p:
            messagebox.showwarning('Aviso', 'Preencha usuário e senha')
            return
        self.username = u
        self.send_json({'action':'login','username':u,'password':p})

    def do_set_name(self):
        if not self.token:
            messagebox.showwarning('Aviso', 'Faça login primeiro')
            return
        name = self.ent_name.get().strip()
        self.send_json({'action':'set_name','token':self.token,'name':name})

    def do_send(self):
        text = self.ent_msg.get().strip()
        if not text:
            return
        if not self.token:
            messagebox.showwarning('Aviso', 'Faça login primeiro')
            return
        self.send_json({'action':'send','token':self.token,'text':text})
        self.append_text(f'[{time.strftime("%H:%M:%S")}] ', 'time')
        self.append_text('Você: ', 'me')
        self.append_text(f'{text}\n')
        self.ent_msg.delete(0, 'end')

    def set_status(self, s, color='#FFFFFF'):
        self.status.configure(text=s, text_color=color)

if __name__ == '__main__':
    root = ctk.CTk()
    app = ChatClient(root)
    root.mainloop()