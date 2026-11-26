"use client";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="ru">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          padding: "24px",
          background:
            "radial-gradient(ellipse at 62% 42%, rgba(229, 169, 61, 0.06), transparent 65%), #0B0E14",
          color: "#f4f3ee",
          fontFamily: "var(--font-geist, system-ui), sans-serif",
        }}
      >
        <div
          style={{
            maxWidth: "520px",
            width: "100%",
            textAlign: "center",
            padding: "40px 32px",
            borderRadius: "24px",
            border: "1px solid rgba(255, 255, 255, 0.05)",
            background:
              "linear-gradient(135deg, #151921 0%, #0B0E14 100%)",
            boxShadow: "0 30px 80px rgba(0, 0, 0, 0.5)",
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              margin: "0 auto 24px",
              display: "grid",
              placeItems: "center",
              borderRadius: 16,
              border: "1px solid rgba(239, 68, 68, 0.2)",
              background: "rgba(239, 68, 68, 0.1)",
              color: "#ef9292",
              fontSize: 28,
            }}
            aria-hidden="true"
          >
            ⚠
          </div>
          <h1
            style={{
              margin: 0,
              fontSize: 24,
              fontWeight: 700,
              letterSpacing: "-0.02em",
              color: "#fff",
            }}
          >
            Приложение упало
          </h1>
          <p
            style={{
              margin: "12px 0 0",
              fontSize: 14,
              lineHeight: 1.6,
              color: "#9b9da5",
            }}
          >
            Произошла критическая ошибка. Обнови страницу или попробуй позже.
          </p>
          <div
            style={{
              marginTop: 28,
              display: "flex",
              gap: 8,
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            <button
              onClick={reset}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "12px 20px",
                borderRadius: 12,
                border: "1px solid #E5A93D",
                background: "#E5A93D",
                color: "#17120a",
                fontSize: 14,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Попробовать снова
            </button>
          </div>
          {error.digest && (
            <p
              style={{
                margin: "24px 0 0",
                fontSize: 11,
                color: "#747985",
              }}
            >
              Код ошибки: <code style={{ fontFamily: "monospace" }}>{error.digest}</code>
            </p>
          )}
        </div>
      </body>
    </html>
  );
}