/*
  borm -- blink ORM library in C++.

  Copyright (c) 2018 <zhang.wei01@blink.com>


Usage:

    struct person
    {
        int id;
        std::string name;
        int gender;
        int score;

        borm(id | name | gender | score)
    };

    struct person_stats
    {
        int count;
        int64_t sum;

        borm(count _as_ "count(1)" | sum _as_ "sum(score)")
    };

    uint64_t dy_id = 1357812409145;
    table t(ctx, shard("dynamic_index_", dy_id, 10), shard("t_revs_", dy_id, 1000, 10));

    // If succeed, return_code >= 0, is affect_rows or queried_rows,  otherwise failed, return_code < 0.
    
    // [NORMAL SQL]
    // `execute` for insert/update/delete
    int rc = t.execute("insert into `tbl` (`id`,`status`) values (1, 0),(2, 1)");
    if(rc < 0) return rc;
    return 0;

    t.execute("update `tbl` set `status`=0 where `id`=1");
    t.execute("delete from `tbl` where `id`=1");

    // `query` for select
    int rows = t.query("select `id`,`status` from `tbl` where `id`=1");
    if(rows < 0) return rows;

    // then use mysql c-wrapper functions by table
    for (int i = 0; i < rows; ++i) {
        MYSQL_ROW row = mysql_fetch_row(t->res);
        unsigned long* lens = mysql_fetch_lengths(t->res);
        if(!row || !lens) return -10002;
        // fetch row[0...fields],lens[0...fields]
        // int fields = mysql_num_fields(t->res);
    }

    // [ORM FUNCTIONS]
    person p = {1, "orca", 1, 99};
    int rc = t.insert(p);
    if(rc < 0) return rc;
    return 0;

    vector<person> ps;
    ps.push_back(p);

    t.insert(&p);
    t.insert(ps);
    t.insert(&ps);
    t.insert(req, borm_f(id|name _as_ "p_name"), on_duplicate_key_update(borm_f(name)));
    t.insert(req->info(), on_duplicate_key_update(borm_f(name), "status=0"));
    t.insert(req->mutable_info(), borm_f(id|name _as_ "p_name"));

    t.update(req, borm_f(id|name),
        where(nz(id) && (ze(name) || nz(score)))
    );
    t.update(set_kvs("status=0"),
        where(nz(id) && (ze(name) || nz(score)))
    );

    t.select(&p, where(le(id, 55)));
    t.select(&ps, borm_f(id|name), 
        where(gt(id, 10)), 
        limit(0, 200)
    );
    t.select(rsp,
        where(nz(id) && ze(name) || nz(score)),
        group_by(borm_f(id|score))
            .order_by(desc(borm_f(id|name)).asc(borm_f(id)))
            .limit(100)
    );
    t.select(rsp->mutable_persons(), borm_f(id|name),
        where(nz(id)),
        order_by(desc(borm_f(id)))
            .limit(0, 200)
    );
    t.select(rsp,
        where(cond("id!=1 and weight=2 and score>3")),
        group_by("id,score").order_by("id,ctime desc, score asc")
    );
    t.select(rsp,
        where_cond("id!=1 and weight=2 and score>3"),
        where_ext("group by id,score order by id,ctime desc, score asc limit 0,300")
    );

    t.del(where(cond("id!=1 and weight=2 and score>3")));
    t.del(where(ne(id, 1) && eq(weight, 2) && gt(score, 3) || (ge(id, 4) && lt(weight, 5) || le(score, 6))));
    t.del(where(nz(id) && cond("(id!=0 or ctime!=0) or score=0")));
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <inttypes.h>

#include <google/protobuf/message.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/repeated_field.h>

#define _as_ |

#define borm(members)\
    static borm::schema& get_schema() { static borm::schema s(#members); return s; }\
    borm::archive& serialize(borm::archive& db, const schema* filter) const { db.set(get_schema(), filter); return db | members; }\
    borm::archive& serialize(borm::archive& db, const schema* filter) { db.set(get_schema(), filter); return db | members; }

#define borm_f(fields) borm::schema(#fields)

#define nz(k)     borm::cond(borm::field_escape(#k) + "!=0"    , 0)
#define ze(k)     borm::cond(borm::field_escape(#k) + "=0"     , 0)
#define in(k, v)  borm::cond(borm::field_escape(#k) + " in (" + borm::to_str(v) + ")", 0)
#define ne(k, v)  borm::cond(borm::field_escape(#k) + "!=" + borm::to_str(v), 0)
#define eq(k, v)  borm::cond(borm::field_escape(#k) + "="  + borm::to_str(v), 0)
#define gt(k, v)  borm::cond(borm::field_escape(#k) + ">"  + borm::to_str(v), 0)
#define ge(k, v)  borm::cond(borm::field_escape(#k) + ">=" + borm::to_str(v), 0)
#define lt(k, v)  borm::cond(borm::field_escape(#k) + "<"  + borm::to_str(v), 0)
#define le(k, v)  borm::cond(borm::field_escape(#k) + "<=" + borm::to_str(v), 0)

#define sne(k, v) borm::cond(borm::field_escape(#k) + "!=" + borm::escape(v), 0)
#define seq(k, v) borm::cond(borm::field_escape(#k) + "="  + borm::escape(v), 0)
#define sgt(k, v) borm::cond(borm::field_escape(#k) + ">"  + borm::escape(v), 0)
#define sge(k, v) borm::cond(borm::field_escape(#k) + ">=" + borm::escape(v), 0)
#define slt(k, v) borm::cond(borm::field_escape(#k) + "<"  + borm::escape(v), 0)
#define sle(k, v) borm::cond(borm::field_escape(#k) + "<=" + borm::escape(v), 0)

namespace borm
{
    template<class T>
    inline std::string to_str(const T& in) {
        std::stringstream ss;
        ss << in;
        return ss.str();
    }
    template<>
    inline std::string to_str<std::string>(const std::string& in) {
        return in;
    }
    template<class T>
    inline T to(const std::string& in) {
        T t;
        std::stringstream ss(in);
        ss >> t;
        return t;
    }
    template<>
    inline std::string to<std::string>(const std::string& in) {
        return in;
    }

    // TODO: only utf-8 safe here
    inline std::string escape(const std::string& in) {
        std::string out("\'");
        for(size_t i = 0; i < in.size(); ++i) {
            switch (in[i]) {
                case '\n':
                    out += "\\n";
                    break;
                case '\r':
                    out += "\\r";
                    break;
                case '\'':
                case '\"':
                case '\\':
                    out += '\\';
                    // fall-through
                default:
                    out += in[i];
                    break;
            }
        }
        out += '\'';
        return out;
    }

    inline std::string field_escape(const std::string& s) {
        return (!s.empty() && s[0] != '`' && s.find_first_of("( ") == std::string::npos) ? "`" + s + "`" : s;
    }

    struct schema {
        schema(const std::string& schema) {
            std::string::size_type start = 0, end = 0;
            do {
                end = schema.find('|', start);
                std::string::size_type quote = schema.find('\"', start = schema.find_first_not_of(" \t\r\n*&", start));
                if(quote < end) {
                    std::string rename = schema.substr(quote + 1, schema.rfind('\"', end - 1) - quote - 1);
                    _schemas.push_back(rename);
                    std::string orig = schema.substr(start, schema.find_first_of(" \t\r\n", start) - start);
                    _r2o[rename] = orig;
                    _o2r[orig] = rename;
                }
                else {
                    _schemas.push_back(schema.substr(start, schema.find_last_not_of(" \t\r\n", end - 1) - start + 1));
                }
            } while ((start = end + 1));
        }
        const std::string& operator[](size_t i) const { return _schemas[i]; }
        size_t size() const { return _schemas.size(); }
        std::string fields(const schema* filter = 0) const {
            std::string ret;
            for(unsigned i = 0; i < _schemas.size(); ++i) {
                if(!filter || filter->orig_exists(orig_field(i))) {
                    if(!ret.empty()) ret += ',';
                    ret += field_escape(filter ? filter->field_by_orig(orig_field(i)) : _schemas[i]);
                }
            }
            return ret;
        }
        const std::string& orig_field(size_t i) const {
            std::map<std::string, std::string>::const_iterator it = _r2o.find(_schemas[i]);
            return (it == _r2o.end() ? _schemas[i] : it->second);
        }
        const std::string& field_by_orig(const std::string& key) const {
            std::map<std::string, std::string>::const_iterator it = _o2r.find(key);
            return it == _o2r.end() ? key : it->second;
        }
        bool orig_exists(const std::string& key) const {
            return _o2r.count(key) || std::find(_schemas.begin(), _schemas.end(), key) != _schemas.end();
        }
        operator schema* const () const {
            return const_cast<schema*>(this);
        }
    private:
        std::vector<std::string> _schemas;
        std::map<std::string, std::string> _r2o;
        std::map<std::string, std::string> _o2r;
    };

    enum SER_METHOD {
        SER_METHOD_VALS = 1,
        SER_METHOD_KVS  = 2,
        SER_METHOD_FROM_DB = 3,
    };

    template<class T>
    struct enumerator
    {
        virtual bool has_more() = 0;
        virtual T next() = 0;
        virtual enumerator<T>& operator+=(const T&) = 0;
    };

    struct db_enumerator : public enumerator<std::string>
    {
        db_enumerator(char** row, unsigned long* lens, int fields)
            : _row(row)
            , _lens(lens)
            , _fields(fields)
            , _idx(0) {
        }
        virtual bool has_more() {
            return _idx < _fields;
        }
        virtual std::string next() {
            if(_idx < _fields) {
                ++_idx;
                return std::string(_row[_idx - 1], _lens[_idx - 1]);
            }
            return "";
        }
        virtual enumerator<std::string>& operator+=(const std::string& s) {
            return *this;
        }

    private:
        char** _row;
        unsigned long* _lens;
        int _fields;
        int _idx;
    };

    struct rslt_enumerator : public enumerator<std::string>
    {
        virtual bool has_more() {
            return false;
        }
        virtual std::string next() {
            return "";
        }
        virtual enumerator<std::string>& operator+=(const std::string& s) {
            if(!_rslt.empty()) _rslt += ',';
            _rslt += s;
            return *this;
        }
        const std::string& str() {
            return _rslt;
        }

    private:
        std::string _rslt;
    };

    struct archive
    {
        archive(int method, enumerator<std::string>* etor = 0)
            : _method(method)
            , _idx(0)
            , _schema(0)
            , _filter(0)
            , _etor(etor) {
        }
        int method() const { return _method; }
        void set(const schema& s, const schema* f) { _schema = &s; _filter = f; }
        bool skip() { return _filter && !_filter->orig_exists(_schema->orig_field(_idx - 1)); }
        const std::string& next() { const std::string& f = (*_schema)[_idx++]; return _filter ? _filter->field_by_orig(f) : f; }
        void append_rslt(const std::string& s) { if(_etor) (*_etor) += s; }
        std::string from_db() { return _etor ? _etor->next() : ""; }
    private:
        int _method;
        int _idx;
        const schema* _schema;
        const schema* _filter;
        enumerator<std::string>* _etor;
    };

    template<size_t M>
    inline archive& operator _as_(archive& s, const char (&)[M]) { return s; }

    template<class T>
    inline archive& operator|(archive& s, T& v) {
        v.serialize(s);
        return s;
    }

#define BORM_HELPER(spec_type, func) \
    inline archive& operator|(archive& s, const spec_type& v)\
    {\
        const std::string& f = s.next();\
        if(s.skip()) return s;\
        switch(s.method()) {\
            case SER_METHOD_VALS:\
                s.append_rslt(func(v));\
                break;\
            case SER_METHOD_KVS: {\
                std::string str(field_escape(f));\
                str += "=";\
                str += func(v);\
                s.append_rslt(str);\
                break;\
            }\
        }\
        return s;\
    }\
    inline archive& operator|(archive& s, spec_type& v)\
    {\
        const std::string& f = s.next();\
        if(s.skip()) return s;\
        switch(s.method()) {\
            case SER_METHOD_VALS:\
                s.append_rslt(func(v));\
                break;\
            case SER_METHOD_KVS: {\
                std::string str(field_escape(f));\
                str += "=";\
                str += func(v);\
                s.append_rslt(str);\
                break;\
            }\
            case SER_METHOD_FROM_DB:\
                v = to<spec_type>(s.from_db());\
                break;\
        }\
        return s;\
    }

#define BORM_HELPER_ARITHMETIC(type) BORM_HELPER(type, to_str)
    BORM_HELPER_ARITHMETIC(unsigned char)
    BORM_HELPER_ARITHMETIC(signed char)
#ifdef _NATIVE_WCHAR_T_DEFINED
    BORM_HELPER_ARITHMETIC(wchar_t)
#endif /* _NATIVE_WCHAR_T_DEFINED */
    BORM_HELPER_ARITHMETIC(unsigned short)
    BORM_HELPER_ARITHMETIC(signed short)
    BORM_HELPER_ARITHMETIC(unsigned int)
    BORM_HELPER_ARITHMETIC(signed int)
#if (defined (__GNUC__) && !defined(__x86_64__)) || (defined(_WIN32) && !defined(_WIN64))
    BORM_HELPER_ARITHMETIC(unsigned long)
    BORM_HELPER_ARITHMETIC(signed long)
#endif
    BORM_HELPER_ARITHMETIC(uint64_t)
    BORM_HELPER_ARITHMETIC(int64_t)
    BORM_HELPER_ARITHMETIC(float)
    BORM_HELPER_ARITHMETIC(double)
    BORM_HELPER_ARITHMETIC(long double)
    BORM_HELPER_ARITHMETIC(bool)

    BORM_HELPER(std::string, escape)

    namespace detail {
        struct common {
            common(const std::string& str = "")
                : _str(str) {
            }
            std::string str() const {
                return _str;
            }
        protected:
            std::string _str;
        };
    }

    struct where_cond : public detail::common {
        where_cond(const std::string& str) {
            if(!str.empty()) {
                _str = " where ";
                _str += str;
            }
        }
        bool empty() const {
            return _str.empty();
        }
    };

    enum COND_LEVEL {
        COND_LEVEL_AND = 1,
        COND_LEVEL_OR  = 2,
        COND_LEVEL_ALL = 3,
    };

    struct cond : public detail::common {
        cond(const std::string& str = "", int level = COND_LEVEL_ALL)
            : detail::common(str)
            , _level(level) {
        }
        std::string str(int up = COND_LEVEL_ALL) const {
            return _str.empty() ? "" : (_level > up ? "(" + _str + ")" : _str);
        }
        bool empty() const {
            return _str.empty();
        }
    private:
        int _level;
    };

    inline cond operator &&(const cond& lhs, const cond& rhs) {
        if(lhs.empty()) return rhs;
        if(rhs.empty()) return lhs;
        std::string str;
        str += lhs.str(COND_LEVEL_AND);
        str += " and ";
        str += rhs.str(COND_LEVEL_AND);
        return cond(str, COND_LEVEL_AND);
    }

    inline cond operator ||(const cond& lhs, const cond& rhs) {
        if(lhs.empty()) return rhs;
        if(rhs.empty()) return lhs;
        std::string str;
        str += lhs.str(COND_LEVEL_OR);
        str += " or ";
        str += rhs.str(COND_LEVEL_OR);
        return cond(str, COND_LEVEL_OR);
    }

    inline where_cond where(const cond& c) {
        return where_cond(c.str());
    }

    inline where_cond where(const std::string& s) {
        return where_cond(s);
    }

    namespace detail {
        struct _order : public common {
            _order& desc(const schema& fields) {
                for(size_t i = 0; i < fields.size(); ++i) {
                    _str += _str.empty() ? " order by " : ",";
                    _str += field_escape(fields[i]) + " desc";
                }
                return *this;
            }
            _order& asc(const schema& fields) {
                for(size_t i = 0; i < fields.size(); ++i) {
                    _str += _str.empty() ? " order by " : ",";
                    _str += field_escape(fields[i]) + " asc";
                }
                return *this;
            }
        };
    }

    inline detail::_order desc(const schema& fields) {
        return detail::_order().desc(fields);
    }

    inline detail::_order asc(const schema& fields) {
        return detail::_order().asc(fields);
    }

    struct where_ext : public detail::common {
        where_ext(const std::string& str = "") {
            if(!str.empty() && str[0] != ' ') {
                _str = " ";
            }
            _str += str;
        }
        operator const where_ext* () const {
            return this;
        }
    protected:
        where_ext& _group_by(const schema& fields) {
            _str += " group by " + fields.fields();
            return *this;
        }
        where_ext& _order_by(const detail::_order& o) {
            _str += o.str();
            return *this;
        }
        where_ext& _order_by(const std::string& str) {
            _str += str.empty() ? str : " order by " + str;
            return *this;
        }
        where_ext& _limit(int64_t limit) {
            _str += " limit " + to_str(limit);
            return *this;
        }
        where_ext& _limit(int64_t offset, int64_t limit) {
            _str += " limit " + to_str(offset) + "," + to_str(limit);
            return *this;
        }
    };

    struct where_ext_limit : public where_ext {
        where_ext_limit(const std::string& str = "")
            : where_ext(str) {
        }
        where_ext& limit(int64_t limit) {
            return _limit(limit);
        }
        where_ext& limit(int64_t offset, int64_t limit) {
            return _limit(offset, limit);
        }
    };

    struct where_ext_ob : public where_ext {
        where_ext_ob(const std::string& str = "")
            : where_ext(str) {
        }
        where_ext_limit& order_by(const detail::_order& o) {
            return (where_ext_limit&)_order_by(o);
        }
        where_ext_limit& order_by(const std::string& str) {
            return (where_ext_limit&)_order_by(str);
        }
        where_ext& limit(int64_t limit) {
            return _limit(limit);
        }
        where_ext& limit(int64_t offset, int64_t limit) {
            return _limit(offset, limit);
        }
    };

    struct where_ext_gb : public where_ext {
        where_ext_gb(const std::string& str = "")
            : where_ext(str) {
        }
        where_ext_ob& group_by(const schema& fields) {
            return (where_ext_ob&)_group_by(fields);
        }
    };

    inline where_ext_ob group_by(const schema& fields) {
        where_ext_gb ext;
        return ext.group_by(fields);
    }

    inline where_ext_ob group_by(const std::string& str) {
        return where_ext_ob(str.empty() ? str : " group by " + str);
    }

    inline where_ext_limit order_by(const detail::_order& o) {
        where_ext_ob ext;
        return ext.order_by(o);
    }

    inline where_ext_limit order_by(const std::string& str) {
        return where_ext_limit(str.empty() ? str : " order by " + str);
    }

    inline where_ext limit(int64_t limit) {
        where_ext_limit ext;
        return ext.limit(limit);
    }

    inline where_ext limit(int64_t offset, int64_t limit) {
        where_ext_limit ext;
        return ext.limit(offset, limit);
    }

    #define borm_pb_filter(return_type) typename borm_enable_if<borm_not<borm_is_base_of<google::protobuf::Message, typename borm_rp_decay<T>::type>::value>::value, return_type>::type

    #define borm_filter(tag, return_type) typename borm_enable_if<borm_is_base_of<tag, typename borm_rp_decay<T>::type>::value, return_type>::type

    // type-traits
    template<bool, typename T = void> struct borm_enable_if   {};
    template<typename T> struct borm_enable_if<true, T>       {typedef T type;};

    template<class T> struct borm_remove_const                {typedef T type;};
    template<class T> struct borm_remove_const<const T>       {typedef T type;};
    template<class T> struct borm_remove_volatile             {typedef T type;};
    template<class T> struct borm_remove_volatile<volatile T> {typedef T type;};
    template<class T> struct borm_remove_cv                   {typedef typename borm_remove_const<typename borm_remove_volatile<T>::type>::type type;};
    template<class T> struct borm_remove_pointer              {typedef T type;};
    template<class T> struct borm_remove_pointer<T*>          {typedef T type;};
    template<class T> struct borm_remove_reference            {typedef T type;};
    template<class T> struct borm_remove_reference<T&>        {typedef T type;};
    template<class T> struct borm_decay                       {typedef typename borm_remove_reference<typename borm_remove_cv<T>::type>::type type;};
    template<class T> struct borm_rp_decay                    {typedef typename borm_remove_pointer<typename borm_decay<T>::type>::type type;};

    template<bool v> struct borm_not                          {enum {value = !v};};

    template<class T1, class T2> struct borm_is_same_         {enum {value = false};};
    template<class T> struct borm_is_same_<T, T>              {enum {value = true};};
    template<class T1, class T2> struct borm_is_same :        borm_is_same_<typename borm_remove_cv<T1>::type, T2> {};

    template <typename B, typename D>
    struct borm_is_base_of
    {
        template <typename T>
        static char helper(D*, T);
        static int helper(B*, int);
        struct conv {
            operator D*();
            operator B*() const;
        };
        static const bool value = sizeof(helper(conv(), int())) == 1;
    };
    // end of type-traits

    inline std::string pb2db(const std::string& key, const google::protobuf::Message* msg) {
        const google::protobuf::Descriptor* d = msg->GetDescriptor();
        const google::protobuf::Reflection* ref = msg->GetReflection();
        if (!d || !ref) return "";

        const google::protobuf::FieldDescriptor* field = d->FindFieldByName(key);
        if(!field) field = ref->FindKnownExtensionByName(key);
        if(!field || field->is_repeated()) return "";

        switch (field->cpp_type()) {
#define _CONVERT(type, func) \
            case google::protobuf::FieldDescriptor::type:       \
                return to_str(ref->func(*msg, field));          \

            _CONVERT(CPPTYPE_DOUBLE, GetDouble);
            _CONVERT(CPPTYPE_FLOAT,  GetFloat);
            _CONVERT(CPPTYPE_INT64,  GetInt64);
            _CONVERT(CPPTYPE_UINT64, GetUInt64);
            _CONVERT(CPPTYPE_INT32,  GetInt32);
            _CONVERT(CPPTYPE_UINT32, GetUInt32);
            _CONVERT(CPPTYPE_BOOL,   GetBool);
#undef _CONVERT
            case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
                return escape(ref->GetString(*msg, field));
            case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
                return to_str(ref->GetEnum(*msg, field)->number());
            default:
                break;
        }
        return "";
    }
    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) fields(T* msg, const schema* filter) {
        if(filter) return filter->fields();

        if(!msg) return "";
        const google::protobuf::Descriptor* d = msg->GetDescriptor();
        if (!d) return "";

        std::string ret;
        for (int i = 0; i < d->field_count(); ++i) {
            const google::protobuf::FieldDescriptor *field = d->field(i);
            if(!field) continue;

            if(!ret.empty()) ret += ",";
            ret += field_escape(field->is_extension() ? field->full_name() : field->name());
        }
        return ret;
    }
    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) fields(T& msg, const schema* filter) {
        return fields(&msg, filter);
    }
    template<class T>
    inline std::string fields(const google::protobuf::RepeatedPtrField<T>* msg, const schema* filter) {
        if(!msg) return "";
        if(msg->size()) {
            return fields(&(msg->Get(0)), filter);
        }
        T t;
        return fields(&t, filter);
    }
    template<class T>
    inline std::string fields(google::protobuf::RepeatedPtrField<T>* msg, const schema* filter) {
        return fields((const google::protobuf::RepeatedPtrField<T>*)msg, filter);
    }
    template<class T>
    inline std::string fields(const google::protobuf::RepeatedPtrField<T>& msg, const schema* filter) {
        return fields(&msg, filter);
    }
    template<class T>
    inline std::string fields(google::protobuf::RepeatedPtrField<T>& msg, const schema* filter) {
        return fields(&msg, filter);
    }
    template<class T>
    inline std::string fields(const std::vector<T>* obj, const schema* filter) {
        return borm_rp_decay<T>::type::get_schema().fields(filter);
    }
    template<class T>
    inline std::string fields(std::vector<T>* obj, const schema* filter) {
        return borm_rp_decay<T>::type::get_schema().fields(filter);
    }
    template<class T>
    inline std::string fields(const std::vector<T>& obj, const schema* filter) {
        return fields(&obj, filter);
    }
    template<class T>
    inline std::string fields(std::vector<T>& obj, const schema* filter) {
        return fields(&obj, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) fields(T* obj, const schema* filter) {
        return T::get_schema().fields(filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) fields(T& obj, const schema* filter) {
        return fields(&obj, filter);
    }

    template<class T>
    inline std::string values(const google::protobuf::RepeatedPtrField<T>* msg, const schema* filter) {
        std::string ret;
        for (int i = 0; i < msg->size(); ++i) {
            if(i) ret += ",";
            ret += values(msg->Get(i), filter);
        }
        return ret;
    }
    template<class T>
    inline std::string values(google::protobuf::RepeatedPtrField<T>* msg, const schema* filter) {
        return values((const google::protobuf::RepeatedPtrField<T>*)msg, filter);
    }
    template<class T>
    inline std::string values(const google::protobuf::RepeatedPtrField<T>& msg, const schema* filter) {
        return values(&msg, filter);
    }
    template<class T>
    inline std::string values(google::protobuf::RepeatedPtrField<T>& msg, const schema* filter) {
        return values(&msg, filter);
    }
    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) values(T* msg, const schema* filter) {
        if(!msg) return "";

        const google::protobuf::Descriptor* d = msg->GetDescriptor();
        if (!d) return "";

        std::string ret;
        if(filter) {
            for (size_t i = 0; i < filter->size(); ++i) {
                if(!ret.empty()) ret += ",";
                ret += pb2db(filter->orig_field(i), msg);
            }
        }
        else {
            for (int i = 0; i < d->field_count(); ++i) {
                const google::protobuf::FieldDescriptor *field = d->field(i);
                if(!field) continue;

                if(!ret.empty()) ret += ",";
                ret += pb2db(field->is_extension() ? field->full_name() : field->name(), msg);
            }
        }
        return " (" + ret + ")";
    }
    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) values(T& msg, const schema* filter) {
        return values(&msg, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) values(T* obj, const schema* filter) {
        if(!obj) return "";
        rslt_enumerator etor;
        archive db(SER_METHOD_VALS, &etor);
        db.set(T::get_schema(), filter);
        obj->serialize(db, filter);
        std::string ret = etor.str();
        return ret.empty() ? ret : " (" + ret + ")";
    }
    template<class T>
    inline borm_pb_filter(std::string) values(T& obj, const schema* filter) {
        return values(&obj, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) values(const std::vector<T>* obj, const schema* filter) {
        std::string ret;
        for (size_t i = 0; i < obj->size(); ++i) {
            if(i) ret += ",";
            ret += values(&(*obj)[i], filter);
        }
        return ret;
    }
    template<class T>
    inline borm_pb_filter(std::string) values(std::vector<T>* obj, const schema* filter) {
        return values((const std::vector<T>*)obj, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) values(const std::vector<T>& obj, const schema* filter) {
        return values(&obj, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) values(std::vector<T>& obj, const schema* filter) {
        return values(&obj, filter);
    }

    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) kvs(T* msg, const schema* filter) {
        if(!msg) return "";

        const google::protobuf::Reflection* ref = msg->GetReflection();
        if (!ref) return "";
        std::vector<const google::protobuf::FieldDescriptor *> fields;
        ref->ListFields(*msg, &fields);

        std::string ret;
        for (size_t i = 0; i < fields.size(); ++i) {
            const google::protobuf::FieldDescriptor *field = fields[i];
            const std::string& name = (field->is_extension()) ? field->full_name() : field->name();

            if(filter && !filter->orig_exists(name)) continue;

            if(!ret.empty()) ret += ",";
            ret += field_escape(filter ? filter->field_by_orig(name) : name);
            ret += "=";
            ret += pb2db(name, msg);
        }
        return ret.empty() ? ret : " " + ret;
    }
    template<class T>
    inline borm_filter(google::protobuf::Message, std::string) kvs(T& msg, const schema* filter) {
        return kvs(&msg, filter);
    }
    template<class T>
    inline borm_pb_filter(std::string) kvs(T* obj, const schema* filter) {
        if(!obj) return "";
        rslt_enumerator etor;
        archive db(SER_METHOD_KVS, &etor);
        db.set(T::get_schema(), filter);
        obj->serialize(db, filter);
        std::string ret = etor.str();
        return ret.empty() ? ret : " " + ret;
    }
    template<class T>
    inline borm_pb_filter(std::string) kvs(T& obj, const schema* filter) {
        return kvs(&obj, filter);
    }

    inline void db2pb(const std::string& key, google::protobuf::Message* msg, const std::string& value) {
        if(!msg) return;

        const google::protobuf::Descriptor* d = msg->GetDescriptor();
        const google::protobuf::Reflection* ref = msg->GetReflection();
        if (!d || !ref) return;

        const google::protobuf::FieldDescriptor* field = d->FindFieldByName(key);
        if(!field) field = ref->FindKnownExtensionByName(key);
        if(!field || field->is_repeated()) return;

        switch (field->cpp_type()) {
            case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
                ref->SetDouble(msg, field, strtod(value.c_str(), NULL));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
                ref->SetFloat(msg, field, strtof(value.c_str(), NULL));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
                ref->SetInt64(msg, field, strtoll(value.c_str(), NULL, 10));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
                ref->SetUInt64(msg, field, strtoull(value.c_str(), NULL, 10));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
                ref->SetInt32(msg, field, atoi(value.c_str()));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
                ref->SetUInt32(msg, field, strtoul(value.c_str(), NULL, 10));
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
                ref->SetString(msg, field, value);
                break;
            case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
                ref->SetEnum(msg, field, field->enum_type()->FindValueByNumber(atoi(value.c_str())));
                break;
            default:
                break;
        }
    }

    template<class T>
    inline bool from_db(google::protobuf::RepeatedPtrField<T>* msg, const schema* filter, db_enumerator* etor) {
        if(!msg) return false;
        from_db(msg->Add(), filter, etor);
        return true;
    }
    template<class T>
    inline bool from_db(google::protobuf::RepeatedPtrField<T>& msg, const schema* filter, db_enumerator* etor) {
        return from_db(&msg, filter, etor);
    }
    inline bool from_db(google::protobuf::Message* msg, const schema* filter, db_enumerator* etor) {
        if(!msg) return false;
        if(!etor) return false;

        if(filter) {
            for (size_t i = 0; i < filter->size(); ++i) {
                db2pb(filter->orig_field(i), msg, etor->next());
            }
        }
        else {
            const google::protobuf::Descriptor* d = msg->GetDescriptor();
            if (!d) return false;

            for (int i = 0; i < d->field_count(); ++i) {
                const google::protobuf::FieldDescriptor *field = d->field(i);
                if(!field) continue;

                db2pb(field->is_extension() ? field->full_name() : field->name(), msg, etor->next());
            }
        }

        return false;
    }
    inline bool from_db(google::protobuf::Message& msg, const schema* filter, db_enumerator* etor) {
        return from_db(&msg, filter, etor);
    }
    template<class T>
    inline borm_pb_filter(bool) from_db(T* obj, const schema* filter, db_enumerator* etor) {
        if(!obj) return false;
        archive db(SER_METHOD_FROM_DB, etor);
        db.set(borm_decay<T>::type::get_schema(), filter);
        obj->serialize(db, filter);
        return true;
    }
    template<class T>
    inline bool from_db(std::vector<T*>* obj, const schema* filter, db_enumerator* etor) {
        if(!obj) return false;
        archive db(SER_METHOD_FROM_DB, etor);
        db.set(borm_decay<T>::type::get_schema(), filter);
        obj->resize(obj->size() + 1);
        obj->back()->serialize(db, filter);
        return true;
    }
    template<class T>
    inline bool from_db(std::vector<T>* obj, const schema* filter, db_enumerator* etor) {
        if(!obj) return false;
        archive db(SER_METHOD_FROM_DB, etor);
        db.set(borm_decay<T>::type::get_schema(), filter);
        obj->resize(obj->size() + 1);
        obj->back().serialize(db, filter);
        return true;
    }

    #undef borm_filter
    #undef borm_pb_filter

    struct on_duplicate_key_update : public detail::common {
        on_duplicate_key_update(const schema* filter, const std::string& ext = "")
            : _filter(filter)
            , _ext(ext) {
        }
        template<class T>
        void set(const T& obj) {
            std::string str = kvs(obj, _filter);
            if(str.empty() && _ext.empty()) return;

            _str = " on duplicate key update";
            _str += str;
            if(!_ext.empty()) {
                _str += str.empty() ? " " : ",";
                _str += _ext;
            }
        }
        operator on_duplicate_key_update* () {
            return const_cast<on_duplicate_key_update*>(this);
        }
    private:
        const schema* _filter;
        std::string _ext;
    };

    struct set_kvs : public detail::common {
        set_kvs(const std::string& str) {
            if(!str.empty() && str[0] != ' ') {
                _str = " ";
            }
            _str += str;
        }
        bool empty() const {
            return _str.empty();
        }
    };

    struct table {
        table(rpc_ctx_t* ctx, const std::string& db, const std::string& name)
            : _ctx(ctx)
            , _query(0)
            , _db(db)
            , _name(field_escape(name)) {
        }

        ~table() {
            close_conn();
        }

        operator mysql_query_t*() {
            return _query;
        }

        mysql_query_t* operator->() {
            return _query;
        }

        int execute(const std::string& sql) {
            int rc = _execute(sql);
            if(rc) return rc > 0 ? -rc : rc;
            return mysql_affected_rows(_query);
        }

        int query(const std::string& sql) {
            int rc = _execute(sql, execute_query);
            if(rc) return rc > 0 ? -rc : rc;
            return mysql_num_rows(_query->res);
        }

        template<class T>
        int insert(const T& obj, on_duplicate_key_update* odku) {
            odku->set(obj);
            return insert(obj, 0, odku->str());
        }

        template<class T>
        int insert(const T& obj, const schema* filter, on_duplicate_key_update* odku) {
            odku->set(obj);
            return insert(obj, filter, odku->str());
        }

        template<class T>
        int insert(const T& obj, const std::string& ext) {
            return insert(obj, ext);
        }

        template<class T>
        int insert(const T& obj, const schema* filter = 0, const std::string& ext = "") {
            std::string sql = "insert into ";
            sql += _name;
            sql += " (";
            sql += fields(obj, filter);
            sql += ") values";
            sql += values(obj, filter);

            if(!ext.empty() && ext[0] != ' ') sql += " ";
            sql += ext;

            int rc = _execute(sql);
            if(rc) return rc > 0 ? -rc : rc;
            return mysql_affected_rows(_query);
        }

        template<class T>
        typename borm_enable_if<borm_not<borm_is_same<set_kvs, typename borm_decay<T>::type>::value>::value, int>::type
        update(const T& obj, const where_cond& cond) {
            return update(obj, 0, cond);
        }

        template<class T>
        int update(const T& obj, const schema* filter, const where_cond& cond) {
            return update(set_kvs(kvs(obj, filter)), cond);
        }

        template<class T>
        typename borm_enable_if<borm_is_same<set_kvs, typename borm_decay<T>::type>::value, int>::type
        update(const T& kvs, const where_cond& cond) {
            if(kvs.empty()) return 0;

            std::string sql = "update ";
            sql += _name;
            sql += " set";
            sql += kvs.str();
            sql += cond.str();
            int rc = _execute(sql);
            if(rc) return rc > 0 ? -rc : rc;
            return mysql_affected_rows(_query);
        }

        int del(const where_cond& cond) {
            if(cond.empty()) return -10002;

            std::string sql = "delete from ";
            sql += _name;
            sql += cond.str();
            int rc = _execute(sql);
            if(rc) return rc > 0 ? -rc : rc;
            return mysql_affected_rows(_query);
        }

        template<class T>
        int select(T* obj, const where_cond& cond, const where_ext* ext = 0) {
            return select(obj, 0, cond, ext);
        }

        template<class T>
        int select(T* obj, const schema* filter, const where_cond& cond, const where_ext* ext = 0) {
            std::string sql = "select ";
            sql += fields(obj, filter);
            sql += " from ";
            sql += _name;
            sql += cond.str();
            if(ext) sql += ext->str();

            int rc = _execute(sql, execute_query);
            if(rc) return rc > 0 ? -rc : rc;

            int rows = mysql_num_rows(_query->res);
            if(!rows) return 0;

            int fields = mysql_num_fields(_query->res);
            for (int i = 0; i < rows; ++i) {
                MYSQL_ROW row = mysql_fetch_row(_query->res);
                unsigned long* lens = mysql_fetch_lengths(_query->res);
                if(!row || !lens) return -10002;
                db_enumerator etor(row, lens, fields);
                if(!from_db(obj, filter, &etor)) break;
            }
            return rows;
        }

    private:
        typedef int (*execute_func)(mysql_query_t* query);
        int _execute(const std::string& sql, execute_func func = execute_mysql_query) {
            rpc_ctx_t* ctx = _ctx;
            LOG(DBG, ctx, "mysql: mysql_id=\"%s\", sql=\"%s\"", _db.c_str(), sql.c_str());
            MYSQL* mysql = get_mysql_from_rpc_by_id(ctx, _db.c_str());
            if(!mysql) {
                LOG(ERR, ctx, "no mysql id for %s", _db.c_str());
                return -10001;
            }
            close_conn();
            _query = mysql_malloc_query(ctx, mysql, sql.c_str());
            int rc = func(_query);
            if(rc) {
                LOG(ERR, ctx, "execute mysql fail: rc=%d, mysql_error=%s", rc, mysql_error(mysql));
                LOG(ERR, ctx, "failed to exeute insert query: query=%s", sql.c_str());
            }
            return rc;
        }

        void close_conn() {
            if(_query) {
                mysql_free_query(_query);
                _query = 0;
            }
        }

        rpc_ctx_t* _ctx;
        mysql_query_t* _query;
        std::string _db;
        std::string _name;
    };

    inline std::string shard(const char* prefix, uint64_t id) {
        return field_escape(prefix + to_str(id));
    }
    inline std::string shard(const char* prefix, uint64_t id, int mod) {
        return shard(prefix, id % mod);
    }
    inline std::string shard(const char* prefix, uint64_t id, int mod, int div) {
        return shard(prefix, id % mod / div);
    }
    inline std::string shard(uint64_t id, const char* postfix) {
        return field_escape(to_str(id) + postfix);
    }
    inline std::string shard(uint64_t id, int mod, const char* postfix) {
        return shard(id % mod, postfix);
    }
    inline std::string shard(uint64_t id, int mod, int div, const char* postfix) {
        return shard(id % mod / div, postfix);
    }
}
/*
namespace redis {

    struct key
    {
        key(rpc_ctx_t* ctx) : _ctx(ctx), _k()
        {
        }

        key(rpc_ctx_t* ctx, const char* fmt, ...)
            : _ctx(ctx)
            , _k()
        {
            va_list args;
            va_start(args, fmt);
            formatv(fmt, args);
            va_end(args);
        }

        int format(const char* fmt, ...) {
            va_list args;
            va_start(args, fmt);
            int ret = vsnprintf(_k, 256, fmt, args);
            va_end(args);
            return ret;
        }
        int formatv(const char* fmt, va_list args) {
            return vsnprintf(_k, 256, fmt, args);
        }

        operator const char*() const {
            return _k;
        }

        template<class T>
        int add(const T& o, int expire = 0) {
            std::string v = borm::to_str(o);
            redisReply* reply = expire ? 
                call_redis(_ctx, "set %s %s ex %d nx", _k, v.c_str(), expire)
                : call_redis(_ctx, "setnx %s %s", _k, v.c_str());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        template<class T>
        int set(const T& o, int expire = 0) {
            std::string v = borm::to_str(o);
            redisReply* reply = expire ?
                call_redis(_ctx, "setex %s %s %d", _k, v.c_str(), expire)
                : call_redis(_ctx, "set %s %s", _k, v.c_str());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        template<class T>
        int get(T& o) {
            redisReply* reply = call_redis(_ctx, "get %s", _k);
            if(!reply || reply->type != REDIS_REPLY_STRING) return -1;
            o = borm::to<T>(std::string(reply->str, reply->len));
            return 1;
        }

        template<class T>
        int take(T& o) {
            redisReply* reply = call_redis(_ctx, "getset %s \"\"", _k);
            if(!reply || reply->type != REDIS_REPLY_STRING) return -1;
            o = borm::to<T>(std::string(reply->str, reply->len));
            return 1;
        }

        int del() {
            redisReply* reply = call_redis(_ctx, "del %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int expire(int seconds) {
            redisReply* reply = call_redis(_ctx, "expire %s %d", _k, seconds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int ttl() {
            redisReply* reply = call_redis(_ctx, "ttl %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

    private:
        rpc_ctx_t* _ctx;
        char _k[256];
    };

    struct pbval : public key
    {
        pbval(rpc_ctx_t* ctx) : key(ctx) {}

        int add(const google::protobuf::Message& msg, int expire = 0) {
            std::string v;
            msg.SerializeToString(&v);
            redisReply* reply = expire ? 
                call_redis(_ctx, "set %s %b ex %d nx", _k, v.data(), v.size(), expire)
                : call_redis(_ctx, "setnx %s %b", _k, v.data(), v.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int set(const google::protobuf::Message& msg, int expire = 0) {
            std::string v;
            msg.SerializeToString(&v);
            redisReply* reply = expire ?
                call_redis(_ctx, "setex %s %b %d", _k, v.data(), v.size(), expire)
                : call_redis(_ctx, "set %s %b", _k, v.data(), v.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int get(google::protobuf::Message& msg) {
            redisReply* reply = call_redis(_ctx, "get %s", _k);
            return (!reply || reply->type != REDIS_REPLY_STRING) ? -1 : msg.ParseFromArray(reply->str, reply->len);
        }

        int take(google::protobuf::Message& msg) {
            redisReply* reply = call_redis(_ctx, "getset %s nil", _k);
            return (!reply || reply->type != REDIS_REPLY_STRING) ? -1 : msg.ParseFromArray(reply->str, reply->len);
        }
    };

    struct intval : public key
    {
        intval(rpc_ctx_t* ctx) : key(ctx) {}

        int incr(int delta = 1) {
            redisReply* reply = (delta == 1) ? call_redis(_ctx, "incr %s", _k) : call_redis(_ctx, "incrby %s %d", _k, delta);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int incr(double delta) {
            redisReply* reply = call_redis(_ctx, "incrbyfloat %s %lf", _k, delta);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int decr(int delta = 1) {
            redisReply* reply = (delta == 1) ? call_redis(_ctx, "decr %s", _k) : call_redis(_ctx, "decrby %s %d", _k, delta);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    struct strval : public key
    {
        strval(rpc_ctx_t* ctx) : key(ctx) {}

        int append(const std::string& s) {
            redisReply* reply = call_redis(_ctx, "append %s %b", _k, s.data(), s.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int substr(std::string& s, int start, int len) {
            redisReply* reply = call_redis(_ctx, "getrange %s %d %d", _k, start , start + len);
            if(!reply || reply->type == REDIS_REPLY_ERROR) return -1;
            s.assign(reply->str, reply->len);
            return reply->len;
        }

        int replace(int start, const std::string& s) {
            redisReply* reply = call_redis(_ctx, "setrange %s %b", _k, s.data(), s.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int length() {
            redisReply* reply = call_redis(_ctx, "strlen %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    struct hash : public key
    {
        hash(rpc_ctx_t* ctx) : key(ctx) {}

        template<class T>
        int hadd(const std::string& m, const T& o) {
            std::string v = to_str(o);
            redisReply* reply = call_redis(_ctx, "hsetnx %s %b %b", _k, m.data(), m.size(), v.data(), v.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        template<class T>
        int hset(const std::string& m, const T& o) {
            std::string v = to_str(o);
            redisReply* reply = call_redis(_ctx, "hset %s %b %b", _k, m.data(), m.size(), v.data(), v.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        template<class T>
        int hget(const std::string& m, T& o) {
            redisReply* reply = call_redis(_ctx, "hget %s %b", _k, m.data(), m.size());
            if(!reply || reply->type != REDIS_REPLY_STRING) return -1;
            o = borm::to<T>(std::string(reply->str, reply->len));
            return 1;
        }

        int hdel(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "hdel %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int hmset(const std::map<std::string, std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("hmset");
            cmds.push_back(_k);
            for (std::map<std::string, std::string>::const_iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(it->first);
                cmds.push_back(it->second);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int hmget(std::map<std::string, std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("hmget");
            cmds.push_back(_k);
            for (std::map<std::string, std::string>::iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(it->first);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            if(!reply || reply->type != REDIS_REPLY_ARRAY || reply->elements != m.size()) return -1;
            size_t i = 0;
            for (std::map<std::string, std::string>::iterator it = m.begin(); it != m.end(); ++it) {
                if(reply->element[i]->str)
                    it->second.assign(reply->element[i]->str, reply->element[i]->len);
                ++i;
            }
            return reply->elements;
        }

        int hgetall(std::map<std::string, std::string>& m) {
            redisReply* reply = call_redis(_ctx, "hgetall %s", _k);
            if(!reply || reply->type != REDIS_REPLY_ARRAY || (reply->elements & 1)) return -1;
            std::string* v = 0;
            for (size_t i = 0; i < reply->elements; ++i) {
                if(i & 1) {
                    if(v && reply->element[i]->str)
                        v->assign(reply->element[i]->str, reply->element[i]->len);
                }
                else {
                    if(reply->element[i]->str)
                        v = &m[std::string(reply->element[i]->str, reply->element[i]->len)];
                }
            }
            return reply->elements;
        }

        int hincr(const std::string& m, int delta) {
            redisReply* reply = call_redis(_ctx, "hincrby %s %b %d", _k, m.data(), m.size(), delta);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int hincr(const std::string& m, double delta) {
            redisReply* reply = call_redis(_ctx, "hincrbyfloat %s %b %lf", _k, m.data(), m.size(), delta);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int hstrlen(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "hstrlen %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int size() {
            redisReply* reply = call_redis(_ctx, "hlen %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    struct set : public key
    {
        set(rpc_ctx_t* ctx) : key(ctx) {}

        int sadd(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "sadd %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int sadd(const std::vector<std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("sadd");
            cmds.push_back(_k);
            for (std::vector<std::string>::const_iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(*it);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int srem(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "srem %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int srem(const std::vector<std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("srem");
            cmds.push_back(_k);
            for (std::vector<std::string>::const_iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(*it);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int size() {
            redisReply* reply = call_redis(_ctx, "scard %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    struct list : public key
    {
        list(rpc_ctx_t* ctx) : key(ctx) {}

        int size() {
            redisReply* reply = call_redis(_ctx, "llen %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    struct zset : public key
    {
        zset(rpc_ctx_t* ctx) : key(ctx) {}

        int zadd(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "zadd %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zadd(const std::vector<std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("zadd");
            cmds.push_back(_k);
            for (std::vector<std::string>::const_iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(*it);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zrem(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "zrem %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zrem(const std::vector<std::string>& m) {
            std::vector<std::string> cmds;
            cmds.push_back("zrem");
            cmds.push_back(_k);
            for (std::vector<std::string>::const_iterator it = m.begin(); it != m.end(); ++it) {
                cmds.push_back(*it);
            }
            redisReply* reply = call_redisv(_ctx, cmds);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zremrangebyrank(int start, int stop) {
            redisReply* reply = call_redis(_ctx, "zremrangebyrank %s %d %d", _k, start, stop);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zcount(int64_t from, int64_t to) {
            redisReply* reply = call_redis(_ctx, "zcount %s %ld %ld", _k, from, to);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zcount(double from, double to) {
            redisReply* reply = call_redis(_ctx, "zcount %s %lf %lf", _k, from, to);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int64_t zincrby(const std::string& m, int64_t delta) {
            redisReply* reply = call_redis(_ctx, "zincrby %s %ld %b", _k, delta, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : strtoll(reply->str, NULL, 10);
        }

        double zincrby(const std::string& m, double delta) {
            redisReply* reply = call_redis(_ctx, "zincrby %s %lf %b", _k, delta, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : strtod(reply->str, NULL);
        }

        template<class T>
        T zscore(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "zscore %s %b", _k, delta, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : (reply->str ? borm::to<T>(reply->str) : 0);
        }

        int zrank(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "zrank %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int zrevrank(const std::string& m) {
            redisReply* reply = call_redis(_ctx, "zrevrank %s %b", _k, m.data(), m.size());
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }

        int size() {
            redisReply* reply = call_redis(_ctx, "zcard %s", _k);
            return (!reply || reply->type == REDIS_REPLY_ERROR) ? -1 : reply->integer;
        }
    };

    // write-once-read-more
    template<class T>
    struct scoped_worm
    {
        int begin() {}
        int begin(T& o) {}
        int end() {}
    };

    template<class T>
    struct scoped_rw
    {
        int begin() {}
        int end() {}
    };

    struct dist_lock
    {
    public:
        dist_lock(rpc_ctx_t* ctx, int expire, const char* fmt, ...)
            : _k(ctx)
            , _expire(expire)
            , _ctx(ctx)
            , _owned(false)
        {
            va_list args;
            va_start(args, fmt);
            _k.formatv(fmt, args);
            va_end(args);

            lock();
        }

        bool is_locked() {
            return _owned;
        }

        bool lock() {
            if (_owned) {
                return true;
            }
            if(_k.add("dummy", _expire) <= 0) {
                LOG(DBG, _ctx, "[get lock (%s) failed] retry next time", _k);
                _owned = false;
            }
            else {
                _owned = true;
            }
            return _owned;
        }

        bool unlock() {
            if (_owned) {
                return _k.del();
            }
            return false;
        }

        ~dist_lock() {
            unlock();
        }

    private:
        key _k;
        int _expire;
        rpc_ctx_t* _ctx;
        bool _owned;
    };
}*/
