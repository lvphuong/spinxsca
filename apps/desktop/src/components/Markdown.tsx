import ReactMarkdown from 'react-markdown';
import { openExternal } from '../lib/shell';

/** Agent-written text: no raw HTML, no images, only https links opened outside the app. */
export function Markdown({ text }: { text: string }) {
  return (
    <ReactMarkdown
      skipHtml
      disallowedElements={['img', 'iframe', 'script', 'style']}
      urlTransform={(url) => (/^https:\/\//i.test(url) ? url : '')}
      components={{
        a: ({ href, children }) => (
          <a
            href={href || undefined}
            onClick={(e) => {
              e.preventDefault();
              if (href) void openExternal(href);
            }}
          >
            {children}
          </a>
        ),
      }}
    >
      {text}
    </ReactMarkdown>
  );
}
