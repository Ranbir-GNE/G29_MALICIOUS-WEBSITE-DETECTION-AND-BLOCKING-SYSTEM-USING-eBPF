import React from "react";
import { useNavigate } from "react-router-dom";
import {
  FaTachometerAlt,
  FaDog,
  FaNotesMedical,
  FaUser,
  FaBalanceScale,
} from "react-icons/fa";

const Sidebar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.setItem("key", null);
    navigate("/");
  };

  return (
    <div className="flex flex-col h-full bg-gray-900 text-white shadow-lg">
      {/* Logo / Header */}
      <div className="flex items-center justify-center p-4 bg-gray-800 border-b border-gray-700">
        <h1 className="text-xl font-bold text-blue-400">eBPF Packet Capture</h1>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 p-4">
        <ul className="space-y-4">
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/dashboard")}
          >
            <FaTachometerAlt className="text-blue-400" />
            <span>Dashboard</span>
          </li>
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/host")}
          >
            <FaDog className="text-blue-400" />
            <span>Hostname Data Usage</span>
          </li>
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/user")}
          >
            <FaNotesMedical className="text-blue-400" />
            <span>User Data Usage</span>
          </li>
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/addrule")}
          >
            <FaBalanceScale className="text-blue-400" />
            <span>Add User Rules</span>
          </li>
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/assignDomain")}
          >
            <FaBalanceScale className="text-blue-400" />
            <span>Assign Domains Page</span>
          </li>
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/addPlans")}
          >
            <FaBalanceScale className="text-blue-400" />
            <span>Assign Rules To Plan</span>
          </li>
        </ul>
      </div>

      {/* Profile and Logout */}
      <div className="p-4 border-t border-gray-700">
        <ul className="space-y-4">
          <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={() => navigate("/profile")}
          >
            <FaUser className="text-blue-400" />
            <span>Profile</span>
          </li>
          {/* <li
            className="flex items-center space-x-3 py-2 px-4 rounded-lg hover:bg-gray-800 cursor-pointer transition"
            onClick={handleLogout}
          >
            <FaSignOutAlt className="text-blue-400" />
            <span>Logout</span>
          </li> */}
        </ul>
      </div>
    </div>
  );
};

export default Sidebar;
