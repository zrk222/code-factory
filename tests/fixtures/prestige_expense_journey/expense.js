const before = document.body.dataset.variant === "before";
const node = (id) => document.getElementById(id);
const editor = node("editor");
const form = node("expense-form");
const confirmation = node("confirmation");
const opener = node("open-expense");
const saveButton = node("save-expense");
const status = node("save-status");
const done = node("done");
const merchant = node("merchant");
const amount = node("amount");
let saving = false;

function openEditor() {
  confirmation.hidden = true;
  opener.disabled = true;
  status.textContent = "";
  form.reset();
  node("save-error").textContent = "";
  editor.hidden = false;
  merchant.focus();
}

opener.addEventListener("click", openEditor);
node("add-another").addEventListener("click", openEditor);
done.addEventListener("click", () => {
  if (before) {
    openEditor();
    return;
  }
  confirmation.hidden = true;
  status.textContent = "";
  opener.disabled = false;
  opener.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (saving) return;
  saving = true;
  saveButton.disabled = true;
  node("save-error").textContent = "";

  try {
    const response = await fetch("/api/expenses", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Fixture-Journey": "expense-save" },
      body: JSON.stringify({ merchant: merchant.value, amount: amount.value }),
    });
    if (!response.ok) throw new Error("Save failed");
    const { merchant: savedMerchant, amount: savedAmount } = await response.json();
    const detail = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" })
      .format(savedAmount) + " · " + savedMerchant;
    const row = document.createElement("li");
    row.textContent = detail;
    node("records").append(row);
    node("empty-records").hidden = true;
    node("expense-detail").textContent = detail;
    editor.hidden = true;
    confirmation.hidden = false;
    status.textContent = "Expense saved. " + detail;
    done.focus();
  } catch {
    node("save-error").textContent = "Expense could not be saved. Try again.";
    saveButton.disabled = false;
    saveButton.focus();
  } finally {
    saving = false;
    saveButton.disabled = false;
  }
});

if (new URLSearchParams(location.search).get("fixture") === "save") {
  openEditor();
  merchant.value = "North Station";
  amount.value = "18.75";
}
