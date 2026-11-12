import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import AuthGate, { installFetchGuard } from "./auth";
import { applySavedTheme } from "./theme";
import "./styles.css";

applySavedTheme();
installFetchGuard();

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthGate>
      <App />
    </AuthGate>
  </React.StrictMode>,
);
