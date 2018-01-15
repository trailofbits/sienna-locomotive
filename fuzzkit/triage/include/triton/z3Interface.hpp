//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_Z3INTERFACE_HPP
#define TRITON_Z3INTERFACE_HPP

#include <triton/dllexport.hpp>
#include <triton/symbolicEngine.hpp>
#include <triton/tritonTypes.hpp>



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The AST namespace
  namespace ast {
  /*!
   *  \ingroup triton
   *  \addtogroup ast
   *  @{
   */

    //! \class Z3Interface
    /*! \brief The interface between Triton and Z3 */
    class Z3Interface {
      private:
        //! Symbolic Engine API
        triton::engines::symbolic::SymbolicEngine* symbolicEngine;

      public:
        //! Constructor.
        TRITON_EXPORT Z3Interface(triton::engines::symbolic::SymbolicEngine* symbolicEngine);

        //! Converts a Triton's AST to a Z3's AST, perform a Z3 simplification and returns a Triton's AST.
        TRITON_EXPORT triton::ast::AbstractNode* simplify(triton::ast::AbstractNode* node) const;

        //! Evaluates a Triton's AST via Z3 and returns a concrete value.
        TRITON_EXPORT triton::uint512 evaluate(triton::ast::AbstractNode *node) const;
    };

  /*! @} End of ast namespace */
  };
/*! @} End of triton namespace */
};

#endif /* TRITON_Z3INTERFACE_HPP */
