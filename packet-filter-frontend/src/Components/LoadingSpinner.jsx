import React from "react";
import spinnerImage from "../assets/loading.png";

const LoadingSpinner = ({ size = "medium", text = "Loading..." }) => {
  const sizeClasses = {
    small: "h-8 w-8",
    medium: "h-16 w-16",
    large: "h-24 w-24"
  };

  return (
    <div 
      role="status"
      aria-label={text}
      className="flex flex-col items-center justify-center mt-6"
    >
      <img 
        src={spinnerImage} 
        alt={text}
        className={`${sizeClasses[size]} animate-spin`}
      />
      <span className="mt-2 text-gray-600">{text}</span>
    </div>
  );
};

export default LoadingSpinner;