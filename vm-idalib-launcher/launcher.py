"""idalib-mcp GUI launcher.

Single-exe entry point. Two modes:
- default: tkinter GUI for configuring + spawning the idalib server
- `--server-mode`: routes to ida_pro_mcp.idalib_server.main()

The GUI launches the server as a subprocess of the same exe with
`--server-mode` so the GUI process never imports `idapro` (which
requires IDA Pro installed on the target machine).
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

SERVER_MODE_FLAG = "--server-mode"


def run_server_mode() -> None:
    sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a != SERVER_MODE_FLAG]
    from ida_pro_mcp.idalib_server import main as server_main

    server_main()


def run_gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("IDA Pro MCP — idalib headless launcher")
    root.geometry("780x560")

    state = {
        "proc": None,
        "reader": None,
        "log_queue": queue.Queue(),
        "stopping": False,
    }

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    for i in range(4):
        frm.columnconfigure(i, weight=1 if i == 1 else 0)

    row = 0
    ttk.Label(frm, text="Host").grid(row=row, column=0, sticky="w", pady=2)
    host_var = tk.StringVar(value="0.0.0.0")
    ttk.Entry(frm, textvariable=host_var, width=20).grid(row=row, column=1, sticky="w")
    ttk.Label(frm, text="(VM host-only: bind 0.0.0.0 so host can reach)").grid(
        row=row, column=2, columnspan=2, sticky="w", padx=6
    )

    row += 1
    ttk.Label(frm, text="Port").grid(row=row, column=0, sticky="w", pady=2)
    port_var = tk.StringVar(value="13777")
    ttk.Entry(frm, textvariable=port_var, width=20).grid(row=row, column=1, sticky="w")

    row += 1
    ttk.Label(frm, text="Initial binary (optional)").grid(
        row=row, column=0, sticky="w", pady=2
    )
    binary_var = tk.StringVar(value="")
    ttk.Entry(frm, textvariable=binary_var).grid(
        row=row, column=1, columnspan=2, sticky="ew", padx=(0, 4)
    )

    def pick_binary():
        p = filedialog.askopenfilename(
            title="Select binary or .i64",
            filetypes=[
                ("IDA databases", "*.i64 *.idb"),
                ("All files", "*.*"),
            ],
        )
        if p:
            binary_var.set(p)

    ttk.Button(frm, text="Browse…", command=pick_binary).grid(
        row=row, column=3, sticky="ew"
    )

    row += 1
    isolated_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frm,
        text="--isolated-contexts (enable idalib_open / idalib_switch)",
        variable=isolated_var,
    ).grid(row=row, column=0, columnspan=4, sticky="w", pady=(6, 0))

    row += 1
    unsafe_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        frm, text="--unsafe (enable destructive tools)", variable=unsafe_var
    ).grid(row=row, column=0, columnspan=4, sticky="w")

    row += 1
    verbose_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(frm, text="--verbose", variable=verbose_var).grid(
        row=row, column=0, columnspan=4, sticky="w"
    )

    row += 1
    ttk.Label(frm, text="IDADIR (IDA install dir, optional)").grid(
        row=row, column=0, sticky="w", pady=(6, 2)
    )
    idadir_var = tk.StringVar(value=os.environ.get("IDADIR", ""))
    ttk.Entry(frm, textvariable=idadir_var).grid(
        row=row, column=1, columnspan=2, sticky="ew", padx=(0, 4)
    )

    def pick_idadir():
        p = filedialog.askdirectory(title="IDA Pro install directory")
        if p:
            idadir_var.set(p)

    ttk.Button(frm, text="Browse…", command=pick_idadir).grid(
        row=row, column=3, sticky="ew"
    )

    row += 1
    btn_frame = ttk.Frame(frm)
    btn_frame.grid(row=row, column=0, columnspan=4, sticky="ew", pady=8)
    start_btn = ttk.Button(btn_frame, text="Start server")
    stop_btn = ttk.Button(btn_frame, text="Stop server", state="disabled")
    start_btn.pack(side="left", padx=4)
    stop_btn.pack(side="left", padx=4)

    status_var = tk.StringVar(value="Stopped")
    ttk.Label(btn_frame, textvariable=status_var, foreground="#666").pack(
        side="left", padx=10
    )

    row += 1
    frm.rowconfigure(row, weight=1)
    log_frame = ttk.LabelFrame(frm, text="Server log", padding=4)
    log_frame.grid(row=row, column=0, columnspan=4, sticky="nsew")
    log_text = tk.Text(log_frame, height=18, wrap="none", bg="#111", fg="#ddd")
    log_text.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    scroll.pack(side="right", fill="y")
    log_text.config(yscrollcommand=scroll.set)

    def append_log(line: str) -> None:
        log_text.insert("end", line)
        log_text.see("end")

    def drain_queue() -> None:
        try:
            while True:
                line = state["log_queue"].get_nowait()
                append_log(line)
        except queue.Empty:
            pass
        root.after(100, drain_queue)

    def reader_thread(proc: subprocess.Popen) -> None:
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                state["log_queue"].put(raw)
        except Exception as e:
            state["log_queue"].put(f"[reader error] {e}\n")
        finally:
            rc = proc.wait()
            if state.get("stopping"):
                state["log_queue"].put(f"\n[server stopped, code={rc}]\n")
            else:
                state["log_queue"].put(f"\n[server exited, code={rc}]\n")
            try:
                root.after(0, on_server_exit)
            except tk.TclError:
                pass

    def on_server_exit() -> None:
        state["proc"] = None
        state["stopping"] = False
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        status_var.set("Stopped")

    def build_cmd() -> list[str]:
        cmd = [sys.executable, SERVER_MODE_FLAG]
        cmd += ["--host", host_var.get().strip() or "0.0.0.0"]
        cmd += ["--port", port_var.get().strip() or "13777"]
        if isolated_var.get():
            cmd.append("--isolated-contexts")
        if unsafe_var.get():
            cmd.append("--unsafe")
        if verbose_var.get():
            cmd.append("--verbose")
        bp = binary_var.get().strip()
        if bp:
            cmd.append(bp)
        return cmd

    def start_server() -> None:
        if state["proc"] is not None:
            return
        try:
            int(port_var.get())
        except ValueError:
            messagebox.showerror("Invalid port", f"Port must be integer: {port_var.get()}")
            return

        env = os.environ.copy()
        idadir = idadir_var.get().strip()
        if idadir:
            env["IDADIR"] = idadir

        cmd = build_cmd()
        append_log(f"\n$ {' '.join(cmd)}\n")

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                env=env,
                creationflags=creationflags,
            )
        except Exception as e:
            messagebox.showerror("Failed to start server", str(e))
            return

        state["proc"] = proc
        state["stopping"] = False
        t = threading.Thread(target=reader_thread, args=(proc,), daemon=True)
        t.start()
        state["reader"] = t
        start_btn.config(state="disabled")
        stop_btn.config(state="normal")
        status_var.set(f"Running (pid {proc.pid})")

    def stop_server() -> None:
        proc = state["proc"]
        if proc is None:
            return
        status_var.set("Stopping…")
        state["stopping"] = True
        try:
            if proc.poll() is None:
                # Windowed PyInstaller launchers have no console. Sending
                # CTRL_BREAK_EVENT calls os.kill() on Windows and can raise
                # SystemError("<built-in function kill> ...") instead of
                # stopping the child. terminate() is the reliable path here.
                proc.terminate()
        except Exception as e:
            append_log(f"[stop warning] terminate failed: {e}\n")

        def force_kill_after():
            if state["proc"] is proc and proc.poll() is None:
                try:
                    proc.kill()
                except Exception as e:
                    append_log(f"[force kill warning] kill failed: {e}\n")

        root.after(3000, force_kill_after)

    start_btn.config(command=start_server)
    stop_btn.config(command=stop_server)

    def on_close():
        if state["proc"] is not None:
            if not messagebox.askokcancel(
                "Quit", "Server is still running. Stop it and quit?"
            ):
                return
            stop_server()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(100, drain_queue)
    root.mainloop()


def main() -> None:
    if SERVER_MODE_FLAG in sys.argv[1:]:
        run_server_mode()
        return
    run_gui()


if __name__ == "__main__":
    main()
