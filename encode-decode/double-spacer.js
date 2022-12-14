function process(helper, value){
    // Replace any character (except last) with the character and a space
    return helper.newResult(value.replaceAll(".(?=.)", "$0 ").trim());
}
