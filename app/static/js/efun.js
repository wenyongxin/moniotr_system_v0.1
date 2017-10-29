$().ready(function() {
	$("#add").click(function(){
		$("#first option:selected").appendTo($("#second"));
	});
	$("#add_all").click(function() {
		$("#first option").appendTo($("#second"));
	});
	$("#first").dblclick(function(){
		$("#first option:selected").appendTo($("#second"));
	});
	
	$("#remove").click(function() {
		$("#second option:selected").appendTo($("#first"));
	});
	$("#remove_all").click(function() {
		$("#second option").appendTo($("#first"));
	});
	
});
