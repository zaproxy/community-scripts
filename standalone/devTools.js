function describeObject(object){
  try {
    print('========= Methods '+object.class+' =========');
    for each(var m in object.class.getDeclaredMethods()){
      print(m)
    }
    print('--- Fields ---');
    for each(var f in object.class.getDeclaredFields()){
      print(f)
    }
    print('========= Methods =========');
  } catch(e) {
    //describeObject(e.getStackTrace())
    print("Caught " + e);
    for each(var st in e.getStackTrace()) print(st);
  }
}

function getFieldByReflection(object, field_name){
  var field = object.class.getDeclaredField(field_name)
  field.setAccessible(true)
  return field.get(object)

}

function getMethodByReflection(object,  method_name){
  var method = object.class.getDeclaredMethod(method_name)
  method.setAccessible(true)
  return method

}

function getConstructors(object){
  var constructors = object.getClass().getDeclaredConstructors()
  for each(var c in constructors) print(c);
}


