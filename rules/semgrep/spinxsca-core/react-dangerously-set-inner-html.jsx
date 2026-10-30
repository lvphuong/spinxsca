export function A({ user }) {
  // ruleid: react-dangerously-set-inner-html
  return <div className="bio" dangerouslySetInnerHTML={{ __html: user.bio }} />;
}

export function B({ user }) {
  // ok: react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />;
}

export function C() {
  // ok: react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;
}
