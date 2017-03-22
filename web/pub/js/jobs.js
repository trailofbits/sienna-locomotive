/*
** TODO:
** 		
*/


/*
** SYSTEM
*/

function systemList(empty_list=false) {
	$.ajax({
		type: 'GET',
		url: '/sys_list',
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 

			var order = data['order'];
			var systems = data['systems'];

			// save the order for use in systemSelect
			$('#system_div').data('order', order);

			// store current and empty
			var selected = $('#system_select').val();
			$('#system_select').empty();

			// add placeholder
			var empty_opt = $('<option></option>');
			empty_opt.text('--');
			empty_opt.val('--');
			$('#system_select').append(empty_opt);

			// add systems
			for(var idx in systems) {
				system = systems[idx];
				var opt = $('<option></option>');
				opt.text(system['name']);
				opt.val(system['_id']);
				opt.addClass('system_option');
				opt.data('system', system);
				$('#system_select').append(opt);
			}

			// restore current
			var child = $('#system_select').children('[value='+selected+']');
			if(!empty_list && child.length == 1) {
				$('#system_select').val(selected);
			} else {
				empty();
			}
		}
	});
}

function systemAdd() {
	var yaml = $("#system_add_yaml").val();
	$.ajax({
		type: 'POST',
		url: '/sys_add', 
		data: {'yaml': yaml}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			systemId = data['system_id'];
			console.log(systemId);
			// TODO: have sys_add return system_list so we don't make two requests
			systemList(true);
		}
	});
}

function systemSelect() {
	var option = $('#system_select').children(':selected');
	var system = option.data('system');
	console.log(system);

	if(system == undefined) {
		empty();
		return;
	}

	var order = $('#system_div').data('order');
	displayConfig(system, 'system', order, []);
	programList();
}

function systemDelete() {
	var system_id = $('#system_select').val();
	$.ajax({
		type: 'POST',
		url: '/sys_delete', 
		data: {'system_id': system_id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			systemList(true);
		}
	});
}

function systemEdit(yaml) {
	var yaml = $("#system_edit_yaml").val();
	var system_id = $('#system_select').val();

	$.ajax({
		type: 'POST',
		url: '/sys_edit', 
		data: {'system_id': system_id, 'yaml': yaml}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			systemId = data['system_id'];
			console.log(systemId);
			// TODO: have sys_add return system_list so we don't make two requests
			systemList(true);
		}
	});
}

function systemInit() {
	$("#system_add_btn").on('click', function() {
		systemAdd();	
	});

	$("#system_edit_btn").on('click', function() {
		systemEdit();
	});

	$("#system_delete_btn").on('click', function() {
		systemDelete();
	});

	$('#system_select').change(systemSelect);

	systemList();
}

/*
** PROGRAM
*/

function programList(empty_list=false) {
	var system_id = $('#system_select').val();
	if(system_id == '--')
		return;

	$.ajax({
		type: 'GET',
		url: '/prog_list/' + system_id,
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 

			var order_gui = data['order_gui'];
			var order_cmd = data['order_cmd'];
			var programs = data['programs'];

			// save the order for use in programSelect
			$('#program_div').data('order_gui', order_gui);
			$('#program_div').data('order_cmd', order_cmd);

			// store current and empty
			var selected = $('#program_select').val();
			$('#program_select').empty();

			// add placeholder
			var empty_opt = $('<option></option>');
			empty_opt.text('--');
			empty_opt.val('--');
			$('#program_select').append(empty_opt);

			// add programs
			for(var idx in programs) {
				program = programs[idx];
				var opt = $('<option></option>');

				switch(program['_cls']) {
					case 'Program.ProgramAutoIT':
						var type = 'gui';
						break;
					case 'Program.ProgramCMD':
						var type = 'cmd';
						break;
					default:
						var type = 'unk';
						brea
				}

				var prefix = '(' + type.toUpperCase() + ') ';
				opt.text(prefix + program['name']);
				opt.val(program['_id']);

				opt.data('program', program);
				opt.data('type', type);
				opt.addClass('program_option');

				$('#program_select').append(opt);
			}

			// restore current
			var child = $('#program_select').children('[value='+selected+']');
			if(!empty_list && child.length == 1) {
				$('#program_select').val(selected);
			} else {
				emptyProgram();
			}

		}
	});
}

function programAddGUI() {
	var yaml = $("#program_add_yaml").val();
	
	var system_id = $('#system_select').val();
	yaml += '\nsystem:\n';
	yaml += ' ' + system_id;
	
	$.ajax({
		type: 'POST',
		url: '/prog_add_gui', 
		data: {'yaml': yaml}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			programId = data['program_id'];
			console.log(programId);
			// TODO: have prog_add return program_list so we don't make two requests
			programList(true);
		}
	});
}

function programAddCMD() {
	var yaml = $("#program_add_yaml").val();
	
	var system_id = $('#system_select').val();
	yaml += '\nsystem:\n';
	yaml += ' ' + system_id;

	$.ajax({
		type: 'POST',
		url: '/prog_add_cmd', 
		data: {'yaml': yaml}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			programId = data['program_id'];
			console.log(programId);
			// TODO: have prog_add return program_list so we don't make two requests
			programList(true);
		}
	});
}

function programSelect() {
	var option = $('#program_select').children(':selected');
	var program = option.data('program');
	var type = option.data('type');
	console.log(program);

	if(program == undefined) {
		emptyProgram();
		return;
	}

	var order = $('#program_div').data('order_'+type);
	displayConfig(program, 'program', order, ['system']);
}

function programDelete() {
	var program_id = $('#program_select').val();
	$.ajax({
		type: 'POST',
		url: '/prog_delete', 
		data: {'program_id': program_id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			programList(true);
		}
	});
}

function programEdit(yaml) {
	var yaml = $("#program_edit_yaml").val();
	var program_id = $('#program_select').val();

	$.ajax({
		type: 'POST',
		url: '/prog_edit', 
		data: {'program_id': program_id, 'yaml': yaml}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			programId = data['program_id'];
			console.log(programId);
			// TODO: have prog_add return program_list so we don't make two requests
			programList(true);
		}
	});
}

function programInit() {
	$("#program_add_gui_btn").on('click', function() {
		programAddGUI();	
	});

	$("#program_add_cmd_btn").on('click', function() {
		programAddCMD();	
	});

	$("#program_edit_btn").on('click', function() {
		programEdit();
	});

	$("#program_delete_btn").on('click', function() {
		programDelete();
	});

	$('#program_select').change(programSelect);

	// programList();
}


/*
** MISC
*/

function displayConfig(config, prefix, order, skip) {
	console.log(order);
	var id_prefix = '#' + prefix;
	var yaml = '';

	$(id_prefix+'_info_div').empty();
	for(var idx in order) {
		var key = order[idx];
		if(skip.indexOf(key) > -1)
			continue;

		var value = config[key];

		var label = $('<h3></h3>');
		label.text(key);
		$(id_prefix+'_info_div').append(label);

		if(typeof(value) == 'string' 
			|| typeof(value) == 'boolean'
			|| typeof(value) == 'number') {
			yaml += key + ':\n';
			if(typeof(value) == 'string')
				yaml += ' \'' + value + '\'\n';
			else
				yaml += ' ' + value + '\n';

			var content = $('<div></div>');
			content.addClass('config_content');
			content.text(value);
			$(id_prefix+'_info_div').append(content);
		} else if(typeof(value) == 'object' && Array.isArray(value)) {
			console.log(value);
			yaml += key + ':\n';

			for(var idx in value) {
				var content = $('<div></div>');
				content.addClass('config_content');
				content.text(value[idx]);
				$(id_prefix+'_info_div').append(content);
				yaml += ' - \'' + value[idx] + '\'\n';
			}
		} 
	}
	$(id_prefix+'_edit_yaml').val(yaml);
}

function emptyProgram() {
	$('#program_add_yaml').val('');
	$('#program_info_div').empty();
	$('#program_edit_yaml').val('');
	$('.run_option').remove();
}

function emptySystem() {
	$('#system_add_yaml').val('');
	$('#system_info_div').empty();
	$('#system_edit_yaml').val('');
	$('.program_option').remove();
}

function empty() {
	emptySystem();
	emptyProgram();
}

function handleError(data) {
	console.log('ERROR: ', data['message']);
	$('#error_span').text(data['message']);
	$('#error_div').show();
}

$(document).ready(function() {
	$('#error_div').hide();
	
	$('#error_dismiss_btn').on('click', function() {
		$('#error_div').hide();
	});

	systemInit();
	programInit();
});

/* OLD */

function pollTask(taskId) {
	$.ajax({
		type: 'GET',
		url: '/task_status/' + taskId,
		success: function(data) {
			console.log(data);
			if(data == 'PENDING') {
				setTimeout(function() {
					pollTask(taskId);
				}, 500);
			} else {
				fetchJobs();
			}
		}
	});
}

function startRun(run_id) {
	$.ajax({
		type: 'POST',
		url: '/run', 
		data: {'run_id': run_id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			taskId = data['task_id'];
			console.log(taskId);
			// pollTask(taskId);
		}
	});
}

function killRun(run_id) {
	$.ajax({
		type: 'POST',
		url: '/run_kill', 
		data: {'run_id': run_id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			// pollTask(taskId);
		}
	});
}
