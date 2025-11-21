import React, { useState } from 'react';

interface Props {
  children: React.ReactNode;
}

// Default password for all posts
const SECRET_PASSWORD = "admin";

export default function PasswordProtected({ children }: Props) {
  const [unlocked, setUnlocked] = useState(false);
  const [input, setInput] = useState('');
  const [error, setError] = useState(false);

  const unlock = () => {
    if (input === SECRET_PASSWORD) {
      setUnlocked(true);
    } else {
      setError(true);
      setInput('');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      unlock();
    }
  };

  if (unlocked) {
    return <div className="w-full max-w-3xl mx-auto p-6">{children}</div>;
  }

  return (
    <div className="w-full max-w-3xl mx-auto p-6 bg-foreground/5 rounded-xl flex flex-col gap-4">
      <p className="text-lg text-foreground/80">
        This post is password-protected. Enter the password to continue:
      </p>
      <input
        type="password"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyPress}
        placeholder="Enter password"
        className="px-4 py-2 rounded border border-foreground/20 focus:outline-none focus:ring-2 focus:ring-accent"
      />
      <button
        onClick={unlock}
        className="px-6 py-2 bg-accent text-white rounded hover:bg-accent/80 transition"
      >
        Unlock
      </button>
      {error && <p className="text-red-500">Incorrect password, try again.</p>}
    </div>
  );
}
