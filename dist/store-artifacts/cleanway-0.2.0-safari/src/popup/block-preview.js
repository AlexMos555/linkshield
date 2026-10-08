const domainInput = document.getElementById('domain-input');
    const brandInput = document.getElementById('brand-input');
    const showBtn = document.getElementById('show-block');

    function render() {
      const existing = document.getElementById('ls-block-overlay');
      if (existing) existing.remove();
      document.body.style.overflow = '';

      const domain = domainInput.value.trim() || 'scam-example.com';
      const brand = brandInput.value.trim();
      const reasons = brand ? [{ detail: `Typosquat of ${brand}` }] : [];
      window.__cleanwayShowBlockPage({ domain, score: 95, reasons });
    }

    showBtn.addEventListener('click', render);
    // Auto-render on page load
    render();
