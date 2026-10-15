// Order search page script — INTENTIONALLY VULNERABLE demo for PandaShield AI.
const params = new URLSearchParams(location.search);
const query = params.get('q') || '';

document.getElementById('search-title').innerHTML = 'Results for ' + query;

async function loadOrders() {
  const res = await fetch('/orders?status=' + encodeURIComponent(query));
  const orders = await res.json();
  const list = document.getElementById('orders');
  orders.forEach((o) => {
    list.innerHTML += `<li>${o.product_name} — ${o.customer_note}</li>`;
  });
}

loadOrders();
