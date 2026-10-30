import DOMPurify from 'dompurify';

export function Bio({ user }) {
  // Vulnerable: attacker-controlled HTML rendered without sanitization.
  return <div className="bio" dangerouslySetInnerHTML={{ __html: user.bio }} />;
}

export function Signature({ user }) {
  // Safe: sanitized before rendering.
  return <div className="signature" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.signature) }} />;
}

export function Title({ title }) {
  // Safe: React escapes text children.
  return <h1>{title}</h1>;
}
