  <script>
    const API = 'http://localhost:8000';

    async function handleReset(e) {
      e.preventDefault();
      const errEl = document.getElementById('resetError');
      const okEl  = document.getElementById('resetSuccess');
      const btn   = e.target.querySelector('button[type="submit"]');
      errEl.style.display = 'none';
      okEl.style.display  = 'none';

      const pass  = document.getElementById('resetPassword').value;
      const pass2 = document.getElementById('resetPassword2').value;

      if (pass !== pass2) {
        errEl.textContent = 'הסיסמאות אינן תואמות';
        errEl.style.display = 'block';
        return;
      }
      if (pass.length < 6) {
        errEl.textContent = 'הסיסמה חייבת להכיל לפחות 6 תווים';
        errEl.style.display = 'block';
        return;
      }

      btn.textContent = '⏳ מעדכן...';
      btn.disabled = true;

      try {
        const r = await fetch(`${API}/auth/reset-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email:        document.getElementById('resetEmail').value,
            new_password: pass,
          }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'שגיאה באיפוס הסיסמה');

        okEl.textContent = '✅ הסיסמה עודכנה בהצלחה! מעביר להתחברות...';
        okEl.style.display = 'block';
        document.getElementById('resetForm').querySelector('button').style.display = 'none';
        setTimeout(() => { window.location.href = 'login.html'; }, 2500);

      } catch (err) {
        errEl.textContent = err.message;
        errEl.style.display = 'block';
        btn.textContent = 'עדכן סיסמה';
        btn.disabled = false;
      }
    }
  </script>