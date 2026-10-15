# RippleGuard v2 (Flask + MongoDB Atlas + HTML/CSS/JS)

## Run in VS Code (Windows)
Terminal 1 (backend):
    cd backend
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python app.py            -> http://127.0.0.1:5100  (terminal shows the database mode)

Terminal 2 (frontend):
    cd frontend
    python -m http.server 5600   -> open http://127.0.0.1:5600

Shortcut: double-click run_all.bat (starts both and opens the browser).

## Roles (each role sees only its own modules)
Admin, Supply Chain Manager, Procurement Officer, Warehouse Manager, Risk Analyst, Supplier.
All roles with the SAME company name share one workspace (same data, live notifications).
Each browser tab keeps its own login, so you can open several roles side by side.

## Test flow
1. Register 3 accounts with the same company name (e.g. Admin, Warehouse Manager, Supplier). OTP is shown on screen.
2. Admin: Dashboard -> "Load demo workspace".
3. Supplier tab: Disruptions -> add an incident. Admin tab gets a toast + voice alert automatically.
