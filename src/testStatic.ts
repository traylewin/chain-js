/* eslint-disable max-classes-per-file */

// Example of static members on a Typescript interface
// See: https://stackoverflow.com/questions/13955157/how-to-define-static-property-in-typescript-interface/59134002#59134002

interface MyType {
  instanceMethod(): string
}

interface MyTypeStatic {
  new (): MyType
  staticMethod(): string
}

// ok
const MyTypeClass: MyTypeStatic = class MyTypeClass {
  public static staticMethod() {
    return 'static result'
  }

  instanceMethod() {
    return 'instanceMethod result'
  }

  someMethod() {
    return 'someMethod'
  }
}

const myClass = new MyTypeClass()
console.log(MyTypeClass.staticMethod())
console.log(myClass.instanceMethod())

// // error: 'instanceMethod' is missing
// const MyTypeClass1: MyTypeStatic = class MyTypeClass {
//   public static staticMethod() {}
// }

// // error: 'staticMethod' is missing
// const MyTypeClass2: MyTypeStatic = class MyTypeClass {
//   instanceMethod() {}
// }

export { MyTypeClass }
