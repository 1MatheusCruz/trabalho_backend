import json
import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import re

DATA_DIR = "../../../../Downloads/sghss_dados"
os.makedirs(DATA_DIR, exist_ok=True)
PACIENTES_ARQ = os.path.join(DATA_DIR, "pacientes.json")
PROFISSIONAIS_ARQ = os.path.join(DATA_DIR, "profissionais.json")
CONSULTAS_ARQ = os.path.join(DATA_DIR, "consultas.json")
PRONTUARIOS_ARQ = os.path.join(DATA_DIR, "prontuarios.json")
USUARIOS_ARQ = os.path.join(DATA_DIR, "usuarios.json")

def codificar(s): return base64.b64encode(s.encode()).decode()
def decodificar(s): return base64.b64decode(s.encode()).decode()
def validar_cpf(cpf): return re.fullmatch(r"\d{11}", cpf)
def validar_data(data): 
    try: datetime.strptime(data, "%d/%m/%Y"); return True
    except: return False
def carregar_arquivo(caminho):
    if os.path.exists(caminho) and os.path.getsize(caminho) > 0:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def salvar_arquivo(caminho, dados):
    with open(caminho, "w", encoding="utf-8") as f: json.dump(dados, f, indent=2)

USUARIOS = carregar_arquivo(USUARIOS_ARQ)
if not USUARIOS:
    USUARIOS = {"admin": {"senha": "admin123", "perfil": "admin"}}
    salvar_arquivo(USUARIOS_ARQ, USUARIOS)

USUARIO_ATUAL = None
usuario_logado = ""

class SGHSSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SGHSS")
        self.geometry("800x600")
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        self.criar_tela_pacientes()
        self.criar_tela_profissionais()
        self.criar_tela_consultas()
        self.criar_tela_prontuarios()

        tk.Button(self, text="Logout", command=self.logout).pack(side="bottom", pady=5)

    # Aplica máscara de data no formato DD/MM/AAAA conforme o usuário digita
    def aplicar_mascara_data_manual(self, entry):
        texto = entry.get().replace("/", "")
        novo = ""
        if len(texto) > 0: novo += texto[:2]
        if len(texto) > 2: novo += "/" + texto[2:4]
        if len(texto) > 4: novo += "/" + texto[4:8]
        entry.delete(0, tk.END)
        entry.insert(0, novo)

    # Aplica máscara de hora no formato HH:MM conforme o usuário digita
    def aplicar_mascara_hora_manual(self, entry):
        texto = entry.get().replace(":", "")
        novo = ""
        if len(texto) > 0:
            novo += texto[:2]
        if len(texto) > 2:
            novo += ":" + texto[2:4]
        entry.delete(0, tk.END)
        entry.insert(0, novo)

    def logout(self):
        self.destroy()
        iniciar_login()

    # Cria a interface da aba de Pacientes, permitindo visualizar, adicionar e (se admin) excluir pacientes
    def criar_tela_pacientes(self):
        if USUARIO_ATUAL == "paciente":
            return
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Pacientes")
        tree = ttk.Treeview(frame, columns=("nome", "cpf", "nascimento"), show="headings")
        for col in ("nome", "cpf", "nascimento"):
            tree.heading(col, text=col.capitalize())
        tree.pack(fill="both", expand=True)

        def atualizar():
            tree.delete(*tree.get_children())
            pacientes = carregar_arquivo(PACIENTES_ARQ)
            usuarios = carregar_arquivo(USUARIOS_ARQ)
            alterado = False
            for p in pacientes:
                cpf = p.get("cpf")
                if cpf and cpf not in usuarios:
                    usuarios[cpf] = {"senha": cpf, "perfil": "paciente"}
                    alterado = True
            if alterado:
                salvar_arquivo(USUARIOS_ARQ, usuarios)
                messagebox.showinfo("Novo login criado", "Paciente cadastrado com sucesso também foi adicionado como usuário.")
            for p in pacientes:
                tree.insert("", tk.END, values=(p["nome"], p["cpf"], p["data_nascimento"]))

        def adicionar():
            win = tk.Toplevel(self)
            win.title("Novo Paciente")
            nome = tk.Entry(win)
            cpf = tk.Entry(win)
            nasc = tk.Entry(win)
            nasc.bind("<KeyRelease>", lambda e: self.aplicar_mascara_data_manual(nasc))
            for lbl, ent in zip(["Nome", "CPF", "Nascimento"], [nome, cpf, nasc]):
                tk.Label(win, text=lbl).pack(); ent.pack()

            def salvar():
                if not (nome.get() and validar_cpf(cpf.get()) and validar_data(nasc.get())):
                    return messagebox.showerror("Erro", "Dados inválidos.")
                pacientes = carregar_arquivo(PACIENTES_ARQ)
                if any(p["cpf"] == cpf.get() for p in pacientes):
                    return messagebox.showerror("Erro", "Paciente já cadastrado.")
                pacientes.append({"nome": nome.get(), "cpf": cpf.get(), "data_nascimento": nasc.get()})
                salvar_arquivo(PACIENTES_ARQ, pacientes)
                win.destroy(); atualizar()

            tk.Button(win, text="Salvar", command=salvar).pack(pady=5)

        tk.Button(frame, text="Adicionar", command=adicionar).pack(pady=5)
        atualizar()

        def excluir():
            if USUARIO_ATUAL != "admin":
                return messagebox.showwarning("Acesso negado", "Apenas administradores podem excluir pacientes.")
            sel = tree.selection()
            if not sel: return
            cpf_sel = tree.item(sel)["values"][1]
            dados = [p for p in carregar_arquivo(PACIENTES_ARQ) if p["cpf"] != cpf_sel]
            salvar_arquivo(PACIENTES_ARQ, dados)
            atualizar()

        tk.Button(frame, text="Excluir", command=excluir).pack(pady=5)

    # Cria a interface da aba de Profissionais, permitindo visualizar e cadastrar médicos
    def criar_tela_profissionais(self):
        if USUARIO_ATUAL == "paciente":
            return
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Profissionais")
        tree = ttk.Treeview(frame, columns=("nome", "crm", "especialidade"), show="headings")
        for col in ("nome", "crm", "especialidade"):
            tree.heading(col, text=col.capitalize())
        tree.pack(fill="both", expand=True)

        def atualizar():
            tree.delete(*tree.get_children())
            profissionais = carregar_arquivo(PROFISSIONAIS_ARQ)
            usuarios = carregar_arquivo(USUARIOS_ARQ)
            alterado = False
            for p in profissionais:
                crm = p.get("crm")
                if crm and crm not in usuarios:
                    usuarios[crm] = {"senha": crm, "perfil": "prosissionais"}
                    alterado = True
            if alterado:
                salvar_arquivo(USUARIOS_ARQ, usuarios)
                messagebox.showinfo("Novo login criado",
                                    "Profissional cadastrado com sucesso também foi adicionado como usuário.")
            for p in profissionais:
                tree.insert("", tk.END, values=(p["nome"], p["crm"], p["especialidade"]))

        def adicionar():
            win = tk.Toplevel(self); win.title("Novo Profissional")
            nome = tk.Entry(win); crm = tk.Entry(win); esp = tk.Entry(win)
            for lbl, ent in zip(["Nome", "CRM", "Especialidade"], [nome, crm, esp]):
                tk.Label(win, text=lbl).pack(); ent.pack()

            def salvar():
                dados = carregar_arquivo(PROFISSIONAIS_ARQ)
                dados.append({"nome": nome.get(), "crm": crm.get(), "especialidade": esp.get()})
                salvar_arquivo(PROFISSIONAIS_ARQ, dados)
                win.destroy(); atualizar()

            tk.Button(win, text="Salvar", command=salvar).pack(pady=5)

        tk.Button(frame, text="Adicionar", command=adicionar).pack(pady=5)
        atualizar()

        def excluir():
            if USUARIO_ATUAL != "admin":
                return messagebox.showwarning("Acesso negado", "Apenas administradores podem excluir profissionais.")
            sel = tree.selection()
            if not sel: return
            nome_sel = tree.item(sel)["values"][0]
            dados = [p for p in carregar_arquivo(PROFISSIONAIS_ARQ) if p["nome"] != nome_sel]
            salvar_arquivo(PROFISSIONAIS_ARQ, dados)
            atualizar()

        tk.Button(frame, text="Excluir", command=excluir).pack(pady=5)

        # Continua a função de consultas:
        # Cria a interface da aba de Consultas, permitindo agendar novas consultas e visualizar as existentes
    def criar_tela_consultas(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Consultas")
        tree = ttk.Treeview(frame, columns=("paciente", "data", "hora", "medico"), show="headings")
        tree.heading("paciente", text="Paciente")
        tree.heading("data", text="Data")
        tree.heading("hora", text="Hora")
        tree.heading("medico", text="Médico")
        tree.heading("data", text="Data/Hora")
        tree.pack(fill="both", expand=True)

        def atualizar():
            tree.delete(*tree.get_children())

            # Adiciona pacientes como usuários automaticamente se não existirem
            pacientes = carregar_arquivo(PACIENTES_ARQ)
            usuarios = carregar_arquivo(USUARIOS_ARQ)
            alterado = False
            for p in pacientes:
                cpf = p.get("cpf")
                if cpf and cpf not in usuarios:
                    usuarios[cpf] = {"senha": cpf, "perfil": "paciente"}
                    alterado = True
            if alterado:
                salvar_arquivo(USUARIOS_ARQ, usuarios)
            for c in carregar_arquivo(CONSULTAS_ARQ):
                if USUARIO_ATUAL == "paciente" and c["paciente"] != usuario_logado:
                    continue
                tree.insert("", tk.END, values=(c["paciente"], c["data"], c["hora"], c.get("medico", "")))

        def agendar():
            win = tk.Toplevel(self);
            win.title("Nova Consulta")
            cpf = tk.Entry(win);
            data = tk.Entry(win);
            hora = tk.Entry(win);
            medico = tk.Entry(win)
            data.bind("<KeyRelease>", lambda e: self.aplicar_mascara_data_manual(data))
            hora.bind("<KeyRelease>", lambda e: self.aplicar_mascara_hora_manual(hora))
            for lbl, ent in zip(["CPF Paciente", "Data", "Hora", "Médico"], [cpf, data, hora, medico]):
                tk.Label(win, text=lbl).pack();
                ent.pack()

            def salvar():
                data_str = data.get().strip()
                hora_str = hora.get().strip()
                nome_medico = medico.get().strip()
                profissionais = carregar_arquivo(PROFISSIONAIS_ARQ)
                if not any(p['nome'] == nome_medico for p in profissionais):
                    return messagebox.showerror("Erro", "Médico não cadastrado.")
                if not validar_cpf(cpf.get()):
                    return messagebox.showerror("Erro", "CPF inválido.")
                pacientes = carregar_arquivo(PACIENTES_ARQ)
                paciente_nome = next((p["nome"] for p in pacientes if p["cpf"] == cpf.get()), None)
                if not paciente_nome:
                    return messagebox.showerror("Erro", "Paciente não cadastrado.")
                try:
                    dt = datetime.strptime(f"{data_str} {hora_str}", "%d/%m/%Y %H:%M")
                    if dt < datetime.now(): raise Exception
                except:
                    return messagebox.showerror("Erro", "Data/hora inválida ou no passado.")
                dados = carregar_arquivo(CONSULTAS_ARQ)
                dados.append({"paciente": paciente_nome, "data": data_str, "hora": hora_str, "medico": nome_medico})
                salvar_arquivo(CONSULTAS_ARQ, dados)
                win.destroy();
                atualizar()

            tk.Button(win, text="Salvar", command=salvar).pack()

        tk.Button(frame, text="Agendar Consulta", command=agendar).pack(pady=5)
        atualizar()

        def excluir():
            if USUARIO_ATUAL != "admin":
                return messagebox.showwarning("Acesso negado", "Apenas administradores podem excluir consultas.")
            sel = tree.selection()
            if not sel: return
            item = tree.item(sel)["values"]
            dados = [c for c in carregar_arquivo(CONSULTAS_ARQ)
                     if not (c["paciente"] == item[0] and c["data"] == item[1] and c["hora"] == item[2])]
            salvar_arquivo(CONSULTAS_ARQ, dados)
            atualizar()

        tk.Button(frame, text="Excluir", command=excluir).pack(pady=5)

    # Cria a interface da aba de Prontuários, com visualização e inserção (por médicos) de registros clínicos
    def criar_tela_prontuarios(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Prontuários")
        tree = ttk.Treeview(frame, columns=("paciente", "descricao", "medico", "data"), show="headings")
        tree.heading("paciente", text="Paciente")
        tree.heading("descricao", text="Descrição")
        tree.heading("medico", text="Médico")
        tree.pack(fill="both", expand=True)

        def atualizar():
            tree.delete(*tree.get_children())
            for p in carregar_arquivo(PRONTUARIOS_ARQ):
                if USUARIO_ATUAL == "paciente" and p["paciente"] != usuario_logado:
                    continue
            tree.insert("", tk.END, values=(p["paciente"], p["descricao"], p.get("medico", ""), p.get("data", "")))

        def adicionar():
            if USUARIO_ATUAL == "paciente":
                return messagebox.showwarning("Acesso negado", "Pacientes não podem adicionar prontuários.")
            win = tk.Toplevel(self)
            win.title("Novo Prontuário")
            cpf = tk.Entry(win)
            desc = tk.Text(win, height=4)
            tk.Label(win, text="CPF").pack(); cpf.pack()
            tk.Label(win, text="Descrição").pack(); desc.pack()

            def salvar():
                if not validar_cpf(cpf.get()):
                    return messagebox.showerror("Erro", "CPF inválido.")
                pacientes = carregar_arquivo(PACIENTES_ARQ)
                paciente_nome = next((p["nome"] for p in pacientes if p["cpf"] == cpf.get()), None)
                if not paciente_nome:
                    return messagebox.showerror("Erro", "Paciente não cadastrado.")
                profissionais = carregar_arquivo(PROFISSIONAIS_ARQ)
                if not any(p['nome'] == usuario_logado for p in profissionais):
                    return messagebox.showerror("Erro", "Apenas médicos cadastrados podem criar prontuários.")
                data_registro = datetime.now().strftime("%d/%m/%Y %H:%M")
                dados = carregar_arquivo(PRONTUARIOS_ARQ)
                dados.append({"paciente": paciente_nome, "descricao": desc.get("1.0", tk.END).strip(), "medico": usuario_logado, "data": data_registro})
                salvar_arquivo(PRONTUARIOS_ARQ, dados)
                win.destroy(); atualizar()

            tk.Button(win, text="Salvar", command=salvar).pack(pady=5)

        tk.Button(frame, text="Adicionar", command=adicionar).pack(pady=5)
        atualizar()

        def excluir():
            if USUARIO_ATUAL != "admin":
                return messagebox.showwarning("Acesso negado", "Apenas administradores podem excluir prontuários.")
            sel = tree.selection()
            if not sel: return
            item = tree.item(sel)["values"]
            dados = [p for p in carregar_arquivo(PRONTUARIOS_ARQ)
                     if not (p["paciente"] == item[0] and p["descricao"] == item[1])]
            salvar_arquivo(PRONTUARIOS_ARQ, dados)
            atualizar()

        tk.Button(frame, text="Excluir", command=excluir).pack(pady=5)


def iniciar_login():
    global entry_user, entry_senha, login_win
    login_win = tk.Tk(); login_win.title("Login SGHSS")
    tk.Label(login_win, text="Usuário").pack(); entry_user = tk.Entry(login_win); entry_user.pack()
    tk.Label(login_win, text="Senha").pack(); entry_senha = tk.Entry(login_win, show="*"); entry_senha.pack()

    def confirmar():
        global USUARIO_ATUAL, usuario_logado
        usuario = entry_user.get().strip()
        senha = entry_senha.get().strip()
        if usuario in USUARIOS and USUARIOS[usuario]["senha"] == senha:
            USUARIO_ATUAL = USUARIOS[usuario]["perfil"]
            usuario_logado = usuario
            login_win.destroy()
            SGHSSApp().mainloop()
        else:
            messagebox.showerror("Erro", "Usuário ou senha inválidos.")

    tk.Button(login_win, text="Entrar", command=confirmar).pack(pady=10)
    login_win.mainloop()

if __name__ == "__main__":
    iniciar_login()