import React from "react";
import Navbar from "../Components/Navbar";
import Sidebar from "../Components/Sidebar";
import AddRule from "../Components/AddRule";

const AddUserRulePage = () => {
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
            <div className="flex-1 grid grid-cols-1 p-4">
              <div className="col-span-1">
                <AddRule />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddUserRulePage;
