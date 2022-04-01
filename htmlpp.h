#include <sstream>
#include <unordered_map>

namespace htmlpp
{
    using Map = std::unordered_map<std::string, std::string>;
    constexpr const char *nbsp{"&nbsp;"};
    constexpr const char *lt{"&lt;"};
    constexpr const char *amp{"&amp;"};
    constexpr const char *cent{"&cent;"};
    constexpr const char *pound{"&pound;"};
    constexpr const char *yen{"&yen;"};
    constexpr const char *copy{"&copy;"};
    constexpr const char *reg{"&reg;"};

#define MAKE_TAG(fn, tag, endtag)                                          \
    template <typename T>                                                  \
    inline void fn(std::stringstream &ss, const T &inner) { ss << inner; } \
    template <typename T, typename... Args>                                \
    inline void fn(std::stringstream &ss, const T &inner, Args... args)    \
    {                                                                      \
        ss << inner;                                                       \
        fn(ss, args...);                                                   \
    }                                                                      \
    template <typename... Args>                                            \
    inline void fn(std::stringstream &ss, Args... args)                    \
    {                                                                      \
        fn(ss, args...);                                                   \
    }                                                                      \
    template <typename... Args>                                            \
    inline std::string fn(Args... args)                                    \
    {                                                                      \
        std::stringstream ss;                                              \
        ss << "<" << #tag << ">";                                          \
        if (endtag)                                                        \
        {                                                                  \
            fn(ss, args...);                                               \
            ss << "</" << #tag << ">";                                     \
        }                                                                  \
        return ss.str();                                                   \
    }                                                                      \
    inline std::string fn()                                                \
    {                                                                      \
        std::stringstream ss;                                              \
        ss << "<" << #tag << ">";                                          \
        if (endtag)                                                        \
        {                                                                  \
            ss << "</" << #tag << ">";                                     \
        }                                                                  \
        return ss.str();                                                   \
    }                                                                      \
    template <typename... Args>                                            \
    inline std::string fn(const Map &map, Args... args)                    \
    {                                                                      \
        std::stringstream ss;                                              \
        ss << "<" << #tag << " ";                                          \
        for (const auto &pair : map)                                       \
        {                                                                  \
            ss << pair.first << "=\"" << pair.second << "\"";              \
        }                                                                  \
        ss << ">";                                                         \
        if (endtag)                                                        \
        {                                                                  \
            fn(ss, args...);                                               \
            ss << "</" << #tag << ">";                                     \
        }                                                                  \
        return ss.str();                                                   \
    }

#define MAKE_1TAG(tag) MAKE_TAG(tag, tag, 0)
#define MAKE_2TAG(tag) MAKE_TAG(tag, tag, 1)
#define MAKE_1TAG_NAMED(fn, tag) MAKE_TAG(fn, tag, 0)
#define MAKE_2TAG_NAMED(fn, tag) MAKE_TAG(fn, tag, 1)

    MAKE_2TAG(a)
    MAKE_2TAG(abbr)
    MAKE_2TAG(acronym)
    MAKE_2TAG(address)
    MAKE_2TAG(area)
    MAKE_2TAG(b)
    MAKE_2TAG(base)
    MAKE_2TAG(bdo)
    MAKE_2TAG(big)
    MAKE_2TAG(blockquote)
    MAKE_2TAG(body)
    MAKE_1TAG(br)
    MAKE_2TAG(button)
    MAKE_2TAG(caption)
    MAKE_2TAG(cite)
    MAKE_2TAG(code)
    MAKE_2TAG(col)
    MAKE_2TAG(colgroup)
    MAKE_2TAG(dd)
    MAKE_2TAG(del)
    MAKE_2TAG(dfn)
    MAKE_2TAG(div)
    MAKE_2TAG(dl)
    MAKE_2TAG(DOCTYPE)
    MAKE_2TAG(dt)
    MAKE_2TAG(em)
    MAKE_2TAG(fieldset)
    MAKE_2TAG(form)
    MAKE_2TAG(h1)
    MAKE_2TAG(h2)
    MAKE_2TAG(h3)
    MAKE_2TAG(h4)
    MAKE_2TAG(h5)
    MAKE_2TAG(h6)
    MAKE_2TAG(head)
    MAKE_2TAG(html)
    MAKE_1TAG(hr)
    MAKE_2TAG(i)
    MAKE_1TAG(img)
    MAKE_1TAG(input)
    MAKE_2TAG(ins)
    MAKE_2TAG(kbd)
    MAKE_2TAG(label)
    MAKE_2TAG(legend)
    MAKE_2TAG(li)
    MAKE_1TAG(link)
    MAKE_2TAG_NAMED(hmap, map) // map is keyword in c++
    MAKE_1TAG(meta)
    MAKE_2TAG(noscript)
    MAKE_2TAG(object)
    MAKE_2TAG(ol)
    MAKE_2TAG(optgroup)
    MAKE_2TAG(option)
    MAKE_2TAG(p)
    MAKE_2TAG(param)
    MAKE_2TAG(pre)
    MAKE_2TAG(q)
    MAKE_2TAG(samp)
    MAKE_2TAG(script)
    MAKE_2TAG(select)
    MAKE_2TAG(small)
    MAKE_2TAG(span)
    MAKE_2TAG(strong)
    MAKE_2TAG(style)
    MAKE_2TAG(sub)
    MAKE_2TAG(sup)
    MAKE_2TAG(table)
    MAKE_2TAG(tbody)
    MAKE_2TAG(td)
    MAKE_2TAG(textarea)
    MAKE_2TAG(tfoot)
    MAKE_2TAG(th)
    MAKE_2TAG(thead)
    MAKE_2TAG(title)
    MAKE_2TAG(tr)
    MAKE_2TAG(tt)
    MAKE_2TAG(ul)
    MAKE_2TAG(var)

    template <typename T>
    inline void comment(std::stringstream &ss, const T &inner) { ss << inner; }
    template <typename T, typename... Args>
    inline void comment(std::stringstream &ss, const T &inner, Args... args)
    {
        ss << inner;
        comment(ss, args...);
    }
    template <typename... Args>
    inline void comment(std::stringstream &ss, Args... args)
    {
        comment(ss, args...);
    }
    template <typename... Args>
    inline std::string comment(Args... args)
    {
        std::stringstream ss;
        ss << "<!-- ";
        comment(ss, args...);
        ss << " -->";
        return ss.str();
    }
    inline std::string comment()
    {
        return "<!-- -->";
    }

} // namespace htmlpp
