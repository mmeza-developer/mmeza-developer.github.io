(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[888],{1118:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/_app",function(){return n(1181)}])},3412:function(e,t){"use strict";var n,r;Object.defineProperty(t,"__esModule",{value:!0}),function(e,t){for(var n in t)Object.defineProperty(e,n,{enumerable:!0,get:t[n]})}(t,{PrefetchKind:function(){return n},ACTION_REFRESH:function(){return l},ACTION_NAVIGATE:function(){return o},ACTION_RESTORE:function(){return u},ACTION_SERVER_PATCH:function(){return i},ACTION_PREFETCH:function(){return f},ACTION_FAST_REFRESH:function(){return c},ACTION_SERVER_ACTION:function(){return s},isThenable:function(){return a}});let l="refresh",o="navigate",u="restore",i="server-patch",f="prefetch",c="fast-refresh",s="server-action";function a(e){return e&&("object"==typeof e||"function"==typeof e)&&"function"==typeof e.then}(r=n||(n={})).AUTO="auto",r.FULL="full",r.TEMPORARY="temporary",("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},6504:function(e,t,n){"use strict";function r(e,t,n,r){return!1}Object.defineProperty(t,"__esModule",{value:!0}),Object.defineProperty(t,"getDomainLocale",{enumerable:!0,get:function(){return r}}),n(282),("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},3480:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),Object.defineProperty(t,"default",{enumerable:!0,get:function(){return j}});let r=n(8754),l=n(5893),o=r._(n(7294)),u=n(7950),i=n(7387),f=n(6982),c=n(6921),s=n(7727),a=n(1973),d=n(6216),p=n(1722),h=n(6504),x=n(634),b=n(3412),m=new Set;function v(e,t,n,r,l,o){if(o||(0,i.isLocalURL)(t)){if(!r.bypassPrefetchedCheck){let l=t+"%"+n+"%"+(void 0!==r.locale?r.locale:"locale"in e?e.locale:void 0);if(m.has(l))return;m.add(l)}Promise.resolve(o?e.prefetch(t,l):e.prefetch(t,n,r)).catch(e=>{})}}function y(e){return"string"==typeof e?e:(0,f.formatUrl)(e)}let j=o.default.forwardRef(function(e,t){let n,r;let{href:f,as:m,children:j,prefetch:_=null,passHref:g,replace:N,shallow:O,scroll:C,locale:E,onClick:P,onMouseEnter:T,onTouchStart:w,legacyBehavior:M=!1,...R}=e;n=j,M&&("string"==typeof n||"number"==typeof n)&&(n=(0,l.jsx)("a",{children:n}));let k=o.default.useContext(a.RouterContext),A=o.default.useContext(d.AppRouterContext),I=null!=k?k:A,L=!k,S=!1!==_,U=null===_?b.PrefetchKind.AUTO:b.PrefetchKind.FULL,{href:H,as:K}=o.default.useMemo(()=>{if(!k){let e=y(f);return{href:e,as:m?y(m):e}}let[e,t]=(0,u.resolveHref)(k,f,!0);return{href:e,as:m?(0,u.resolveHref)(k,m):t||e}},[k,f,m]),F=o.default.useRef(H),D=o.default.useRef(K);M&&(r=o.default.Children.only(n));let B=M?r&&"object"==typeof r&&r.ref:t,[G,V,X]=(0,p.useIntersection)({rootMargin:"200px"}),q=o.default.useCallback(e=>{(D.current!==K||F.current!==H)&&(X(),D.current=K,F.current=H),G(e),B&&("function"==typeof B?B(e):"object"==typeof B&&(B.current=e))},[K,B,H,X,G]);o.default.useEffect(()=>{I&&V&&S&&v(I,H,K,{locale:E},{kind:U},L)},[K,H,V,E,S,null==k?void 0:k.locale,I,L,U]);let z={ref:q,onClick(e){M||"function"!=typeof P||P(e),M&&r.props&&"function"==typeof r.props.onClick&&r.props.onClick(e),I&&!e.defaultPrevented&&function(e,t,n,r,l,u,f,c,s){let{nodeName:a}=e.currentTarget;if("A"===a.toUpperCase()&&(function(e){let t=e.currentTarget.getAttribute("target");return t&&"_self"!==t||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.nativeEvent&&2===e.nativeEvent.which}(e)||!s&&!(0,i.isLocalURL)(n)))return;e.preventDefault();let d=()=>{let e=null==f||f;"beforePopState"in t?t[l?"replace":"push"](n,r,{shallow:u,locale:c,scroll:e}):t[l?"replace":"push"](r||n,{scroll:e})};s?o.default.startTransition(d):d()}(e,I,H,K,N,O,C,E,L)},onMouseEnter(e){M||"function"!=typeof T||T(e),M&&r.props&&"function"==typeof r.props.onMouseEnter&&r.props.onMouseEnter(e),I&&(S||!L)&&v(I,H,K,{locale:E,priority:!0,bypassPrefetchedCheck:!0},{kind:U},L)},onTouchStart(e){M||"function"!=typeof w||w(e),M&&r.props&&"function"==typeof r.props.onTouchStart&&r.props.onTouchStart(e),I&&(S||!L)&&v(I,H,K,{locale:E,priority:!0,bypassPrefetchedCheck:!0},{kind:U},L)}};if((0,c.isAbsoluteUrl)(K))z.href=K;else if(!M||g||"a"===r.type&&!("href"in r.props)){let e=void 0!==E?E:null==k?void 0:k.locale,t=(null==k?void 0:k.isLocaleDomain)&&(0,h.getDomainLocale)(K,e,null==k?void 0:k.locales,null==k?void 0:k.domainLocales);z.href=t||(0,x.addBasePath)((0,s.addLocale)(K,e,null==k?void 0:k.defaultLocale))}return M?o.default.cloneElement(r,z):(0,l.jsx)("a",{...R,...z,children:n})});("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1722:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),Object.defineProperty(t,"useIntersection",{enumerable:!0,get:function(){return f}});let r=n(7294),l=n(9126),o="function"==typeof IntersectionObserver,u=new Map,i=[];function f(e){let{rootRef:t,rootMargin:n,disabled:f}=e,c=f||!o,[s,a]=(0,r.useState)(!1),d=(0,r.useRef)(null),p=(0,r.useCallback)(e=>{d.current=e},[]);return(0,r.useEffect)(()=>{if(o){if(c||s)return;let e=d.current;if(e&&e.tagName)return function(e,t,n){let{id:r,observer:l,elements:o}=function(e){let t;let n={root:e.root||null,margin:e.rootMargin||""},r=i.find(e=>e.root===n.root&&e.margin===n.margin);if(r&&(t=u.get(r)))return t;let l=new Map;return t={id:n,observer:new IntersectionObserver(e=>{e.forEach(e=>{let t=l.get(e.target),n=e.isIntersecting||e.intersectionRatio>0;t&&n&&t(n)})},e),elements:l},i.push(n),u.set(n,t),t}(n);return o.set(e,t),l.observe(e),function(){if(o.delete(e),l.unobserve(e),0===o.size){l.disconnect(),u.delete(r);let e=i.findIndex(e=>e.root===r.root&&e.margin===r.margin);e>-1&&i.splice(e,1)}}}(e,e=>e&&a(e),{root:null==t?void 0:t.current,rootMargin:n})}else if(!s){let e=(0,l.requestIdleCallback)(()=>a(!0));return()=>(0,l.cancelIdleCallback)(e)}},[c,n,t,s,d.current]),[p,s,(0,r.useCallback)(()=>{a(!1)},[])]}("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1181:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return c}});var r=n(5893);n(9166);var l=n(1664),o=n.n(l);function u(){return(0,r.jsx)("div",{className:"w-full  bg-black",children:(0,r.jsx)("div",{className:"max-w-screen-xl mx-auto",children:(0,r.jsxs)("header",{className:"flex items-center justify-between py-5  ",children:[(0,r.jsx)(o(),{href:"/",className:"px-2 text-xl lg:px-0 font-bold text-orange-400",children:"Github Blog"}),(0,r.jsxs)("ul",{className:"inline-flex items-center",children:[(0,r.jsx)("li",{className:"px-2 md:px-4",children:(0,r.jsx)(o(),{href:"/",className:"text-white font-semibold hover:text-orange-500",children:" Home "})}),(0,r.jsx)("li",{className:"px-2 md:px-4",children:(0,r.jsx)(o(),{href:"/dev",className:"text-white font-semibold hover:text-orange-500",children:" Developerment "})}),(0,r.jsx)("li",{className:"px-2 md:px-4",children:(0,r.jsx)(o(),{href:"/htb",className:"text-white font-semibold hover:text-orange-500",children:" HackTheBox "})}),(0,r.jsx)("li",{className:"px-2 md:px-4",children:(0,r.jsx)(o(),{href:"/pentesting-web",className:"text-white font-semibold hover:text-orange-500",children:" Pentesting Web "})})]})]})})})}function i(){return(0,r.jsx)("footer",{className:"bg-white border-t border-l  ",children:(0,r.jsx)("div",{className:"flex",children:(0,r.jsx)("div",{className:"w-full text-center p-1",children:(0,r.jsx)("h6",{className:"font-semibold text-gray-700 mb-4",children:"A Simple Github Blog - 2024"})})})})}function f(e){let{children:t}=e;return(0,r.jsxs)("div",{className:"flex flex-col h-screen",children:[(0,r.jsx)(u,{}),(0,r.jsx)("main",{className:"flex-grow",children:t}),(0,r.jsx)(i,{})]})}function c(e){let{Component:t,pageProps:n}=e;return(0,r.jsx)(f,{children:(0,r.jsx)(t,{...n})})}},9166:function(){},1664:function(e,t,n){e.exports=n(3480)}},function(e){var t=function(t){return e(e.s=t)};e.O(0,[774,179],function(){return t(1118),t(3035)}),_N_E=e.O()}]);