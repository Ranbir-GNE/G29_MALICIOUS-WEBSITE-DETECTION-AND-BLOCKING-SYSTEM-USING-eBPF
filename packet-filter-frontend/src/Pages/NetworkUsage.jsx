import React from "react";
import Navbar from "../Components/Navbar";
import Sidebar from "../Components/Sidebar";
import PieChart from "../Components/PieChart";
import NetworkTable from "../Components/NetworkTable";
import NetworkTableHostname from "../Components/NetworkTableHostname";
import CumalativeTable from "../Components/CmalativeTable";

const Dashboard = () => {
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
            <div className="flex-1 grid grid-cols-3 gap-4 p-4">
              <div className="col-span-1">
                <PieChart />
              </div>
              <div className="col-span-1">
                <NetworkTable />
              </div>
              <div className="col-span-1">
                <NetworkTableHostname />
              </div>
              <div className="col-span-1">
                <CumalativeTable />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
