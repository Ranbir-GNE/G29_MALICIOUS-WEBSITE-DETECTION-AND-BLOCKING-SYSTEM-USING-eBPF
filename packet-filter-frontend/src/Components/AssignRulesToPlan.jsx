import { useState, useEffect } from "react";
import axios from "axios";

const BASE_URL = import.meta.env.VITE_BASE_URL;

const AssignRulesToPlan = () => {
  const [userRulesMap, setUserRulesMap] = useState({});
  const [users, setUsers] = useState([]);
  const [rules, setRules] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedRule, setSelectedRule] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    fetchUsers();
    fetchRules();
  }, []);

  const fetchUsers = async () => {
    try {
      const userResponse = await axios.get(`${BASE_URL}/api/clients/all`);
      setUsers(userResponse.data);
    } catch (err) {
      setError("Error fetching users");
    }
  };

  const fetchRules = async () => {
    try {
      const rulesResponse = await axios.get(`${BASE_URL}/api/rules/all`);
      const processedRules = rulesResponse.data.map((rule) => ({
        ...rule,
        rules: rule.rules || [],
      }));
      setRules(processedRules);
    } catch (err) {
      setError("Error fetching rules");
    }
  };

  const handleUserSelect = async (user) => {
    setSelectedUser(user);
    setSelectedRule(user.assignedRule || "");
    setError("");

    try {
      const res = await axios.get(`${BASE_URL}/api/rules/${user.ip_address}`);
      setUserRulesMap((prev) => ({
        ...prev,
        [user.ip_address]: res.data || [],
      }));
    } catch (err) {
      setError("Error fetching assigned rules for user");
    }
  };

  const handleAssignRule = async (userId) => {
    if (!selectedRule) {
      setError("Please select a rule");
      return;
    }

    const alreadyAssigned = userRulesMap[userId]?.some(
      (rule) => rule.rule_id === selectedRule
    );

    if (alreadyAssigned) {
      setError("Rule already assigned to this user");
      return;
    }

    setIsLoading(true);
    try {
      await axios.post(`${BASE_URL}/api/plans/add`, {
        user_id: userId,
        rule_id: selectedRule,
      });

      // Fetch updated rules for the user
      const res = await axios.get(`${BASE_URL}/api/rules/${userId}`);
      console.log(res.data);
      setUserRulesMap((prev) => ({
        ...prev,
        [userId]: res.data || [],
      }));

      setSelectedRule("");
      setError("");
    } catch (err) {
      setError("Error adding rule to user");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteRule = async (planId, userId) => {
    if (!planId) {
      setError("Invalid plan ID");
      return;
    }

    setIsLoading(true);
    try {
      await axios.delete(`${BASE_URL}/api/plans/delete/${planId}`);

      // Refresh the user's rules after deletion
      const res = await axios.get(`${BASE_URL}/api/rules/${userId}`);
      setUserRulesMap((prev) => ({
        ...prev,
        [userId]: res.data || [],
      }));

      setError("");
    } catch (err) {
      setError("Error deleting rule");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-2 gap-6 h-screen p-6 bg-gray-100">
      {/* Left - Users */}
      <div className="bg-white shadow-md rounded-lg p-6 overflow-y-auto">
        <h2 className="text-2xl font-semibold text-gray-800 mb-4">Users</h2>
        {users.map((user) => (
          <div
            key={user.ip_address}
            className={`p-4 mb-4 border rounded-lg cursor-pointer transition ${
              selectedUser?.ip_address === user.ip_address
                ? "bg-blue-100 border-blue-500"
                : "bg-gray-50 hover:bg-gray-100"
            }`}
            onClick={() => handleUserSelect(user)}
          >
            <p className="text-gray-700">
              <strong>User ID:</strong> {user.ip_address}
            </p>
            <p className="text-gray-600">{user.name}</p>
          </div>
        ))}
      </div>

      {/* Right - Rules */}
      <div className="bg-white shadow-md rounded-lg p-6 overflow-y-auto">
        <div>
          <h2 className="text-2xl font-semibold text-gray-800 mb-4">Rules</h2>
          {selectedUser ? (
            <>
              <p className="mb-4 text-gray-700">
                <strong>Selected User:</strong> {selectedUser.ip_address}
              </p>

              <select
                className="w-full p-3 border rounded-lg mb-4 text-gray-700"
                value={selectedRule}
                onChange={(e) => setSelectedRule(e.target.value)}
              >
                <option value="">Select a rule</option>
                {rules.map((rule) => (
                  <option key={rule.rule_id} value={rule.rule_id}>
                    {rule.rule_name}
                  </option>
                ))}
              </select>

              <button
                className={`w-full bg-blue-500 text-white px-4 py-2 rounded-lg transition ${
                  isLoading
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-blue-600"
                }`}
                onClick={() => handleAssignRule(selectedUser.ip_address)}
                disabled={isLoading}
              >
                {isLoading ? "Adding Rule..." : "Add Rule"}
              </button>

              {error && <p className="text-red-500 mt-4">{error}</p>}
            </>
          ) : (
            <p className="text-gray-600">
              Please select a user to assign a rule.
            </p>
          )}
        </div>

        <div className="mt-6">
          <h2 className="text-2xl font-semibold text-gray-800 mb-4">
            Assigned Rules
          </h2>
          {selectedUser && userRulesMap[selectedUser.ip_address]?.length > 0 ? (
            userRulesMap[selectedUser.ip_address].map((rule) => (
              <div
                key={rule.plan_id}
                className="p-4 mb-4 border rounded-lg bg-gray-50 flex justify-between items-center"
              >
                <div>
                  <p className="text-gray-700">
                    <strong>Rule ID:</strong> {rule.rule_id}
                  </p>
                  <p className="text-gray-600">{rule.rule_name}</p>
                </div>
                <button
                  onClick={() =>
                    handleDeleteRule(rule.plan_id, selectedUser.ip_address)
                  }
                  className="text-red-500 hover:underline text-sm"
                >
                  Delete
                </button>
              </div>
            ))
          ) : (
            <p className="text-gray-600">No rules assigned to this user.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default AssignRulesToPlan;
