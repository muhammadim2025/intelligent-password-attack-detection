const menuButton = document.getElementById("mobileMenu");
const sidebar = document.getElementById("socSidebar");

if (menuButton && sidebar) {
  menuButton.addEventListener("click", () => sidebar.classList.toggle("open"));
}

window.addEventListener("resize", () => {
  if (sidebar && window.innerWidth > 900) sidebar.classList.remove("open");
});

document.querySelectorAll("[data-countup]").forEach((element) => {
  const target = Number(element.dataset.countup || 0);
  const duration = 550;
  const started = performance.now();
  const animate = (now) => {
    const progress = Math.min((now - started) / duration, 1);
    element.textContent = Math.round(target * progress).toLocaleString();
    if (progress < 1) requestAnimationFrame(animate);
  };
  requestAnimationFrame(animate);
});

function canvasSize(canvas) {
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(320, Math.floor(rect.width * ratio));
  canvas.height = Math.max(180, Math.floor(rect.height * ratio));
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  return { context, width: rect.width, height: rect.height };
}

function drawFallbackGrid(ctx, width, height, pad) {
  ctx.strokeStyle = "rgba(148,163,184,.12)";
  ctx.lineWidth = 1;
  for (let line = 0; line < 5; line++) {
    const y = pad + ((height - pad * 2) * line) / 4;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(width - pad, y);
    ctx.stroke();
  }
}

function drawFallbackAxes(ctx, width, height, pad, xLabel, yLabel) {
  ctx.fillStyle = "#9ca3af";
  ctx.font = "10px Inter, sans-serif";
  if (yLabel) {
    ctx.save();
    ctx.translate(10, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = "center";
    ctx.fillText(yLabel, 0, 0);
    ctx.restore();
  }
  if (xLabel) {
    ctx.textAlign = "center";
    ctx.fillText(xLabel, width / 2, height - 2);
  }
}

function fallbackLine(canvas, values, color, fillColor) {
  fallbackMultiLine(
    canvas,
    (values || []).map((_, index) => String(index + 1)),
    [{ data: values || [0], color, fill: fillColor }],
    { singleBucketAsBar: false }
  );
}

function fallbackMultiLine(canvas, labels, series, options = {}) {
  if (!canvas) return;
  const safeLabels = labels && labels.length ? labels : [""];
  const safeSeries = (series || []).map((item) => ({
    data: (item.data && item.data.length ? item.data : safeLabels.map(() => 0)).map((v) => Number(v) || 0),
    color: item.color || "#3b82f6",
    fill: item.fill || "rgba(59,130,246,.12)",
    label: item.label || "",
  }));
  const { context: ctx, width, height } = canvasSize(canvas);
  const padX = 34;
  const padY = 22;
  const allValues = safeSeries.flatMap((item) => item.data);
  const max = Math.max(...allValues, 1);
  const nonempty = safeLabels.filter((_, i) => allValues.some((_, j) => false) || safeSeries.some((s) => (s.data[i] || 0) > 0)).length;
  const singleBucket = options.singleBucketAsBar || (safeLabels.length === 1 && safeSeries.some((s) => (s.data[0] || 0) > 0));

  ctx.clearRect(0, 0, width, height);
  drawFallbackGrid(ctx, width, height, padY);

  if (singleBucket) {
    const slot = (width - padX * 2) / Math.max(safeSeries.length, 1);
    const barWidth = Math.min(48, slot * 0.45);
    safeSeries.forEach((item, index) => {
      const value = item.data[0] || 0;
      const barHeight = (value / max) * (height - padY * 2);
      const x = padX + slot * index + (slot - barWidth) / 2;
      ctx.fillStyle = item.color;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(x, height - padY - barHeight, barWidth, barHeight, 6);
      else ctx.rect(x, height - padY - barHeight, barWidth, barHeight);
      ctx.fill();
      ctx.fillStyle = "#e5e7eb";
      ctx.font = "11px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(String(value), x + barWidth / 2, Math.max(12, height - padY - barHeight - 6));
    });
  } else {
    safeSeries.forEach((item, seriesIndex) => {
      const points = item.data.map((value, index) => ({
        x: padX + (index * (width - padX * 2)) / Math.max(safeLabels.length - 1, 1),
        y: height - padY - (value / max) * (height - padY * 2),
      }));
      if (item.fill) {
        ctx.beginPath();
        ctx.moveTo(points[0].x, height - padY);
        points.forEach((point) => ctx.lineTo(point.x, point.y));
        ctx.lineTo(points[points.length - 1].x, height - padY);
        ctx.closePath();
        ctx.fillStyle = seriesIndex === 0 ? item.fill : "rgba(239,68,68,.06)";
        ctx.fill();
      }
      ctx.beginPath();
      points.forEach((point, index) => {
        if (index === 0) ctx.moveTo(point.x, point.y);
        else ctx.lineTo(point.x, point.y);
      });
      ctx.strokeStyle = item.color;
      ctx.lineWidth = 2.5;
      ctx.stroke();
      points.forEach((point, index) => {
        const radius = item.data[index] > 0 || safeLabels.length <= 2 ? 4 : 2.5;
        ctx.beginPath();
        ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = item.color;
        ctx.fill();
      });
    });
  }

  ctx.fillStyle = "#9ca3af";
  ctx.font = "9px Inter, sans-serif";
  ctx.textAlign = "center";
  const labelStep = safeLabels.length <= 8 ? 1 : Math.ceil(safeLabels.length / 6);
  safeLabels.forEach((label, index) => {
    if (index % labelStep === 0 || index === safeLabels.length - 1) {
      ctx.fillText(label || "", padX + (index * (width - padX * 2)) / Math.max(safeLabels.length - 1, 1), height - 4);
    }
  });

  // Integer y-axis hints
  ctx.textAlign = "right";
  for (let tick = 0; tick <= 4; tick++) {
    const value = Math.round((max * (4 - tick)) / 4);
    const y = padY + ((height - padY * 2) * tick) / 4;
    ctx.fillText(String(value), padX - 6, y + 3);
  }
  drawFallbackAxes(ctx, width, height, padY, options.xLabel || "", options.yLabel || "Count");
}

function fallbackBars(canvas, values, labels, colors) {
  fallbackGroupedBars(
    canvas,
    labels || (values || []).map((_, i) => String(i + 1)),
    [{ data: values || [0], color: Array.isArray(colors) ? colors[0] : (colors || "#3b82f6") }],
    {}
  );
}

function fallbackGroupedBars(canvas, labels, series, options = {}) {
  if (!canvas) return;
  const safeLabels = labels && labels.length ? labels : [""];
  const safeSeries = (series || []).map((item) => ({
    data: (item.data && item.data.length ? item.data : safeLabels.map(() => 0)).map((v) => Number(v) || 0),
    color: item.color || "#3b82f6",
    label: item.label || "",
  }));
  const { context: ctx, width, height } = canvasSize(canvas);
  const padX = 34;
  const padY = 22;
  const allValues = safeSeries.flatMap((item) => item.data);
  const max = Math.max(...allValues, 1);
  ctx.clearRect(0, 0, width, height);
  drawFallbackGrid(ctx, width, height, padY);
  const groupSlot = (width - padX * 2) / safeLabels.length;
  const groupWidth = groupSlot * 0.72;
  const barWidth = Math.max(4, Math.min(22, groupWidth / Math.max(safeSeries.length, 1)));
  safeLabels.forEach((label, index) => {
    const groupX = padX + groupSlot * index + (groupSlot - groupWidth) / 2;
    safeSeries.forEach((item, sIndex) => {
      const value = item.data[index] || 0;
      const barHeight = (value / max) * (height - padY * 2);
      const x = groupX + sIndex * barWidth;
      ctx.fillStyle = item.color;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(x, height - padY - barHeight, Math.max(2, barWidth - 2), barHeight, 4);
      else ctx.rect(x, height - padY - barHeight, Math.max(2, barWidth - 2), barHeight);
      ctx.fill();
    });
  });
  ctx.fillStyle = "#9ca3af";
  ctx.font = "9px Inter, sans-serif";
  ctx.textAlign = "center";
  const labelStep = safeLabels.length <= 12 ? 1 : Math.ceil(safeLabels.length / 8);
  safeLabels.forEach((label, index) => {
    if (index % labelStep === 0 || index === safeLabels.length - 1) {
      ctx.fillText(label || "", padX + groupSlot * index + groupSlot / 2, height - 4);
    }
  });
  ctx.textAlign = "right";
  for (let tick = 0; tick <= 4; tick++) {
    const value = Math.round((max * (4 - tick)) / 4);
    const y = padY + ((height - padY * 2) * tick) / 4;
    ctx.fillText(String(value), padX - 6, y + 3);
  }
  drawFallbackAxes(ctx, width, height, padY, options.xLabel || "", options.yLabel || "Count");
}

function fallbackDoughnut(canvas, values, colors) {
  const { context: ctx, width, height } = canvasSize(canvas);
  const total = values.reduce((sum, value) => sum + value, 0) || 1;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.32;
  let start = -Math.PI / 2;
  ctx.clearRect(0, 0, width, height);
  values.forEach((value, index) => {
    const angle = (value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, start, start + angle);
    ctx.strokeStyle = colors[index];
    ctx.lineWidth = 17;
    ctx.stroke();
    start += angle;
  });
}

window.socChartFallback = {
  line: fallbackLine,
  multiLine: fallbackMultiLine,
  bars: fallbackBars,
  groupedBars: fallbackGroupedBars,
  doughnut: fallbackDoughnut,
};

if (window.Chart && window.Chart.defaults) {
  Chart.defaults.color = "#aeb8c6";
  Chart.defaults.borderColor = "rgba(255,255,255,.07)";
  Chart.defaults.font.family = '"Inter", system-ui, sans-serif';
}

const socSearch = document.getElementById("socSearch");
if (socSearch) {
  socSearch.addEventListener("input", () => {
    const query = socSearch.value.toLowerCase().trim();
    document.querySelectorAll(".soc-table tbody tr").forEach((row) => {
      row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
    });
  });
}
