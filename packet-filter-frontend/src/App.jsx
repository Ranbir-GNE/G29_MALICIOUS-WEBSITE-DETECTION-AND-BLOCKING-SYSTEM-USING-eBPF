import React, { useState } from "react";
import LoginRegister from "./Pages/LoginRegister";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import Dashboard from "./Pages/Dashboard";
import userContext from "./context/UserContext";
import UserDataUsage from "./Pages/UserDataUsage";
import HostnameDataUsage from "./Pages/HostnameDataUsage";
import ProfilePage from "./Pages/ProfilePage";
import AddUserRulePage from "./Pages/AddUserRulePage";
import AddDomainPage from "./Pages/AddDomainPage";
import { Toaster, toast } from "sonner";
import AssignRulesToPlanPage from "./Pages/AssignRulesToPlanPage";

const App = () => {
  const [loginUser, setLoginUser] = useState();
  return (
    <userContext.Provider value={{ loginUser, setLoginUser }}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LoginRegister />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/user" element={<UserDataUsage />} />
          <Route path="/host" element={<HostnameDataUsage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/addrule" element={<AddUserRulePage />} />
          <Route path="/assignDomain" element={<AddDomainPage />} />
          <Route path="/addPlans" element={<AssignRulesToPlanPage />} />
        </Routes>
        <Toaster />
      </BrowserRouter>
    </userContext.Provider>
  );
};

export default App;
