/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_Y_TAB_H_INCLUDED
# define YY_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    PACKAGE = 258,
    PACKAGE_NAME = 259,
    DEFINE = 260,
    IN_DEFINE = 261,
    IN_DEFINE_OP_TYPE = 262,
    IN_DEFINE_OP_TAG = 263,
    IN_DEFINE_QUERY = 264,
    IN_DEFINE_QUERY_CONTENT = 265,
    IN_DEFINE_COLUMN = 266,
    IN_DEFINE_COLUMN_COLUMN_NAME = 267,
    IN_DEFINE_COLUMN_COLUMN_TYPE = 268,
    IN_DEFINE_COLUMN_COLUMN_MAX_LEN = 269,
    IN_DEFINE_CONDITION = 270,
    IN_DEFINE_CONDITION_COLUMN_NAME = 271,
    IN_DEFINE_CONDITION_COLUMN_TYPE = 272,
    IN_DEFINE_CONDITION_COLUMN_MAX_LEN = 273,
    IN_DEFINE_UPDATE = 274,
    IN_DEFINE_UPDATE_COLUMN_NAME = 275,
    IN_DEFINE_UPDATE_COLUMN_TYPE = 276,
    IN_DEFINE_UPDATE_COLUMN_MAX_LEN = 277,
    DEFINE_END = 278
  };
#endif
/* Tokens.  */
#define PACKAGE 258
#define PACKAGE_NAME 259
#define DEFINE 260
#define IN_DEFINE 261
#define IN_DEFINE_OP_TYPE 262
#define IN_DEFINE_OP_TAG 263
#define IN_DEFINE_QUERY 264
#define IN_DEFINE_QUERY_CONTENT 265
#define IN_DEFINE_COLUMN 266
#define IN_DEFINE_COLUMN_COLUMN_NAME 267
#define IN_DEFINE_COLUMN_COLUMN_TYPE 268
#define IN_DEFINE_COLUMN_COLUMN_MAX_LEN 269
#define IN_DEFINE_CONDITION 270
#define IN_DEFINE_CONDITION_COLUMN_NAME 271
#define IN_DEFINE_CONDITION_COLUMN_TYPE 272
#define IN_DEFINE_CONDITION_COLUMN_MAX_LEN 273
#define IN_DEFINE_UPDATE 274
#define IN_DEFINE_UPDATE_COLUMN_NAME 275
#define IN_DEFINE_UPDATE_COLUMN_TYPE 276
#define IN_DEFINE_UPDATE_COLUMN_MAX_LEN 277
#define DEFINE_END 278

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_Y_TAB_H_INCLUDED  */
