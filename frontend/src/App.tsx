import { useState } from "react";
import Login from "./components/Login";
import Analyzer from "./components/Analyzer";

function App() {
  const [token, setToken] = useState<string | null>(null);

  function handleLogout() {
    setToken(null);
  }

  return token ? (
    <Analyzer token={token} onLogout={handleLogout} />
  ) : (
    <Login onLoginSuccess={setToken} />
  );
}

export default App;
