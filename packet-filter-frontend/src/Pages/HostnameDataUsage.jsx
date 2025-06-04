import React from "react";
import Navbar from "../Components/Navbar";
import Sidebar from "../Components/Sidebar";
import NetworkTableHostname from "../Components/NetworkTableHostname";
import PieChart from "../Components/PieChart";

const HostnameDataUsage = () => {
  return (
    <div className="h-screen flex flex-col">
      <div className="flex-none">
        <Navbar />
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="flex-none w-1/6">
          <Sidebar />
        </div>

        <div className="flex-1 grid grid-cols-12">
          <div className="col-span-10 overflow-y-auto">
            <div className="flex-1 grid grid-cols-2 gap-4 p-4">
              <div className="col-span-1">
                <NetworkTableHostname />
              </div>
              <div className="col-span-1">
                <PieChart />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HostnameDataUsage;
