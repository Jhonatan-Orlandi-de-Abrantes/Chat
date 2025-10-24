import socket, threading, json, tkinter as tk, queue, time
from tkinter import scrolledtext, messagebox

HOST = "192.168.56.1"
PORT = 12345

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Chat Global - Cliente")
        self.sock = None
        self.rfile = None
        self.wfile = None
        self.listener_thread = None
        self.recv_queue = queue.Queue()
        self.token = None
        self.username = None
        self.display_name = None

        top = tk.Frame(master)
        top.pack(padx=8, pady=6, fill="x")

        tk.Label(top, text="Username:").grid(row=0, column=0)
        self.ent_user = tk.Entry(top)
        self.ent_user.grid(row=0, column=1)

        tk.Label(top, text="Senha:").grid(row=0, column=2)
        self.ent_pass = tk.Entry(top, show="*")
        self.ent_pass.grid(row=0, column=3)

        self.btn_register = tk.Button(top, text="Register", command=self.do_register)
        self.btn_register.grid(row=0, column=4, padx=4)
        self.btn_login = tk.Button(top, text="Login", command=self.do_login)
        self.btn_login.grid(row=0, column=5)

        name_frame = tk.Frame(master)
        name_frame.pack(padx=8, pady=4, fill="x")
        tk.Label(name_frame, text="Name (display):").pack(side="left")
        self.ent_name = tk.Entry(name_frame)
        self.ent_name.pack(side="left", padx=6)
        self.btn_set_name = tk.Button(name_frame, text="Set Name", command=self.do_set_name)
        self.btn_set_name.pack(side="left")

        self.txt_area = scrolledtext.ScrolledText(master, state="disabled", width=70, height=20, wrap="word")
        self.txt_area.pack(padx=8, pady=6)

        self.txt_area.tag_config("sys", foreground="#666666")
        self.txt_area.tag_config("me", foreground="#1e90ff")
        self.txt_area.tag_config("user", foreground="#000000")
        self.txt_area.tag_config("time", foreground="#8888aa")

        bottom = tk.Frame(master)
        bottom.pack(padx=8, pady=6, fill="x")
        self.ent_msg = tk.Entry(bottom)
        self.ent_msg.pack(side="left", expand=True, fill="x")
        self.ent_msg.bind("<Return>", lambda e: self.do_send())
        self.btn_send = tk.Button(bottom, text="Send", command=self.do_send)
        self.btn_send.pack(side="left", padx=6)

        self.status = tk.Label(master, text="Desconectado", anchor="w")
        self.status.pack(fill="x", padx=8, pady=(0,8))

        self.connect_to_server(HOST, PORT)

        self.master.after(100, self.process_incoming)

    def connect_to_server(self, host, port):
        try:
            self.sock = socket.create_connection((host, port))
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 60)
            except Exception:
                pass
            self.rfile = self.sock.makefile("r", encoding="utf-8", newline="\n")
            self.wfile = self.sock.makefile("w", encoding="utf-8", newline="\n")
            self.listener_thread = threading.Thread(target=self.listen_loop, daemon=True)
            self.listener_thread.start()
            self.set_status("Conectado")
        except Exception as e:
            messagebox.showerror("Erro", f"Não conseguiu conectar ao servidor: {e}")
            self.set_status("Desconectado")
            self.sock = None
            self.rfile = None
            self.wfile = None

    def listen_loop(self):
        try:
            for line in self.rfile:
                if line is None:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    self.recv_queue.put({"type":"info","message":"Recebido JSON inválido do servidor"})
                    continue
                self.recv_queue.put(obj)
        except Exception as e:
            self.recv_queue.put({"type":"info","message":f"Erro conexão: {e}"})
        finally:
            self.recv_queue.put({"type":"info","message":"desconectado do servidor"})
            try:
                if self.wfile:
                    self.wfile.close()
            except:
                pass
            try:
                if self.rfile:
                    self.rfile.close()
            except:
                pass
            try:
                if self.sock:
                    self.sock.close()
            except:
                pass
            self.sock = None
            self.wfile = None
            self.rfile = None

    def process_incoming(self):
        while True:
            try:
                obj = self.recv_queue.get_nowait()
            except queue.Empty:
                break
            self.handle_server_obj(obj)
        self.master.after(100, self.process_incoming)

    def handle_server_obj(self, obj):
        t = obj.get("type")
        if t == "message":
            ts = time.strftime("%H:%M:%S", time.localtime(obj.get("timestamp", time.time())))
            self.append_text(f"[{ts}] ", "time")
            self.append_text(f"{obj.get('from')}: ", "user")
            self.append_text(f"{obj.get('text')}\n")
        elif t == "info":
            self.append_text(f"[info] {obj.get('message')}\n", "sys")
        elif t == "error":
            messagebox.showerror("Erro do servidor", obj.get("message"))
        elif t == "ok":
            action = obj.get("action")
            if action == "login":
                self.token = obj.get("token")
                self.display_name = obj.get("display_name")
                self.set_status(f"Logado: {self.display_name}")
                self.append_text(f"[sistema] Logado como {self.display_name}\n", "sys")
            elif action == "register":
                messagebox.showinfo("Registro", obj.get("message"))
            elif action == "set_name":
                self.display_name = obj.get("display_name")
                self.set_status(f"Logado: {self.display_name}")
                self.append_text(f"[sistema] Display name atualizado: {self.display_name}\n", "sys")
        elif t == "history":
            msgs = obj.get("messages", [])
            if msgs:
                self.append_text("[sistema] Histórico de mensagens:\n", "sys")
                for m in msgs:
                    ts = time.strftime("%H:%M:%S", time.localtime(m.get("timestamp", time.time())))
                    self.append_text(f"[{ts}] ", "time")
                    self.append_text(f"{m.get('from')}: ", "user")
                    self.append_text(f"{m.get('text')}\n")
        else:
            self.append_text(f"{obj}\n", "sys")

    def append_text(self, text, tag=None):
        self.txt_area.configure(state="normal")
        if tag:
            self.txt_area.insert("end", text, (tag,))
        else:
            self.txt_area.insert("end", text)
        self.txt_area.see("end")
        self.txt_area.configure(state="disabled")

    def send_json(self, obj):
        if not self.wfile:
            messagebox.showerror("Erro", "Não conectado ao servidor")
            return
        try:
            line = json.dumps(obj, ensure_ascii=False)
            self.wfile.write(line + "\n")
            self.wfile.flush()
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao enviar: {e}")

    def do_register(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u or not p:
            messagebox.showwarning("Aviso", "Username e senha necessários")
            return
        self.send_json({"action":"register","username":u,"password":p})

    def do_login(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u or not p:
            messagebox.showwarning("Aviso", "Username e senha necessários")
            return
        self.username = u
        self.send_json({"action":"login","username":u,"password":p})

    def do_set_name(self):
        if not self.token:
            messagebox.showwarning("Aviso", "Faça login primeiro")
            return
        name = self.ent_name.get().strip()
        self.send_json({"action":"set_name","token":self.token,"name":name})

    def do_send(self):
        text = self.ent_msg.get().strip()
        if not text:
            return
        if not self.token:
            messagebox.showwarning("Aviso", "Faça login para enviar mensagens")
            return
        self.send_json({"action":"send","token":self.token,"text":text})
        self.append_text(f"[{time.strftime('%H:%M:%S')}] ", "time")
        self.append_text("Você: ", "me")
        self.append_text(f"{text}\n")
        self.ent_msg.delete(0, "end")

    def set_status(self, s):
        self.status.config(text=s)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()

