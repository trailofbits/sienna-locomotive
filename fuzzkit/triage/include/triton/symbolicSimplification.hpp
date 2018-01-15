//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_SYMBOLICSIMPLIFICATION_H
#define TRITON_SYMBOLICSIMPLIFICATION_H

#include <triton/ast.hpp>
#include <triton/callbacks.hpp>
#include <triton/dllexport.hpp>



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Engines namespace
  namespace engines {
  /*!
   *  \ingroup triton
   *  \addtogroup engines
   *  @{
   */

    //! The Symbolic Execution namespace
    namespace symbolic {
    /*!
     *  \ingroup engines
     *  \addtogroup symbolic
     *  @{
     */

      //! \class SymbolicSimplification
      /*! \brief The symbolic simplification class */
      class SymbolicSimplification {
        private:
          //! Callbacks API
          triton::callbacks::Callbacks* callbacks;

          //! Copies a SymbolicSimplification.
          void copy(const SymbolicSimplification& other);

        public:
          //! Constructor.
          TRITON_EXPORT SymbolicSimplification(triton::callbacks::Callbacks* callbacks=nullptr);

          //! Constructor.
          TRITON_EXPORT SymbolicSimplification(const SymbolicSimplification& other);

          //! Processes all recorded simplifications. Returns the simplified node.
          TRITON_EXPORT triton::ast::AbstractNode* processSimplification(triton::ast::AbstractNode* node) const;

          //! Copies a SymbolicSimplification.
          TRITON_EXPORT void operator=(const SymbolicSimplification& other);
      };

    /*! @} End of symbolic namespace */
    };
  /*! @} End of engines namespace */
  };
/*! @} End of triton namespace */
};

#endif /* TRITON_SYMBOLICSIMPLIFICATION_H */

