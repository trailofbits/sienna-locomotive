function systemList() {
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
				opt.data('system', system);
				$('#system_select').append(opt);
			}

			// restore current
			if($('#system_select').children('[value='+selected+']').length == 1)
				$('#system_select').val(selected);

		}
	});
}

function systemAdd(yaml) {
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
			systemList();
		}
	});
}

function systemSelect() {
	var option = $('#system_select').children(':selected');
	var system = option.data('system');
	console.log(system);

	if(system == undefined) {
		return;
	}

	$('#system_info_div').empty();

	var order = $('#system_div').data('order');
	for(var idx in order) {
		var key = order[idx];
		var value = system[key];

		var label = $('<h3></h3>');
		label.text(key);
		$('#system_info_div').append(label);

		if(typeof(value) == 'string') {
			var content = $('<div></div>');
			content.addClass('config_content');
			content.text(value);
			$('#system_info_div').append(content);
		} else if(typeof(value) == 'object' && Array.isArray(value)) {
			console.log(value);
			for(var idx in value) {
				var content = $('<div></div>');
				content.addClass('config_content');
				content.text(value[idx]);
				$('#system_info_div').append(content);
			}
		}

	}
}

function systemInit() {
	$("#system_add_btn").on('click', function() {
		var yaml = $("#system_add_yaml").val()
		console.log(yaml);
		systemAdd(yaml);	
	});

	$('#system_select').change(systemSelect);

	systemList();
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

function listRuns(results) {
	var body = $("#run_list_body");
	body.empty();
	var keys = schema['run']['order'];
	for(var ridx in results) {
		var result = results[ridx];
		var row = $('<tr></tr>')
		for(kidx in keys) {
			var col = $('<td></td>');
			var key = keys[kidx];
			col.text(result[key]);
			row.append(col);
		}
		var startButton = $('<button>Start</button>');
		var killButton = $('<button>Kill</button>');
		
		// row.append(editButton);
		startButton.on('click', function() {
			var data = {};
			var id = row.children().first().text();
			startRun(id);
		});
		row.append(startButton);

		killButton.on('click', function() {
			console.log('kill');
			var id = row.children().first().text();
			killRun(id);
		});
		row.append(killButton);

		body.append(row);
	}
}

function removeWinaflJob(id) {
	$.ajax({
		type: 'POST',
		url: '/winafl_job_remove', 
		data: {'id': id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			listWinaflJobs(data);
		}
	});
}

function createRunWinaflJob(id) {
	$.ajax({
		type: 'POST',
		url: '/winafl_run_create', 
		data: {'job_id': id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			listRuns(data);
		}
	});
}

function getModOffWinaflJob(id) {
	$.ajax({
		type: 'POST',
		url: 'winafl_job_mod_off', 
		data: {'id': id}, 
		success: function(data) {
			data = JSON.parse(data);
			if('error' in data) {
				handleError(data);
				return;
			} 
			taskId = data['task_id'];
			console.log(taskId);
			pollTask(taskId);
		}
	});
}

function listWinaflJobs(results) {
	var body = $("#winafl_job_list_body");
	body.empty();
	var keys = schema['winafl_job']['order'];
	for(var ridx in results) {
		var result = results[ridx];
		var row = $('<tr></tr>')
		for(kidx in keys) {
			var col = $('<td></td>');
			var key = keys[kidx];
			col.text(result[key]);
			row.append(col);
		}
		var editButton = $('<button>Edit</button>');
		var removeButton = $('<button>Remove</button>');
		var runButton = $('<button>Create Run</button>');
		
		// row.append(editButton);
		removeButton.on('click', function() {
			var row = $(this).parent();
			var id = row.children().first().text();
			console.log(id);
			removeWinaflJob(id);
		});
		row.append(removeButton);

		var modoffButton = $('<button></button>');
		modoffButton.text('Mod Off');
		modoffButton.on('click', function() {
			var data = {};
			var id = row.children().first().text();
			getModOffWinaflJob(id);
		});
		row.append(modoffButton);

		runButton.on('click', function() {
			var row = $(this).parent();
			var id = row.children().first().text();
			console.log(id);
			createRunWinaflJob(id);
		});
		row.append(runButton);

		body.append(row);
	}
}

function fetchJobs() {
	$.getJSON('/winafl_job_list', listWinaflJobs);
}

function fetchRuns() {
	$.getJSON('/run_list', listRuns);
}

function buildJob(schema, schemaKey) {
	var idBase = schemaKey;
	var idAdd = idBase + '_add';
	var idList = idBase + '_list';
	var keys = schema[schemaKey]['order'];

	for(var idx in keys) {
		var key = keys[idx];
		var type = schema[schemaKey][key]['type'];
		var required = schema[schemaKey][key]['required'];
		var colName = keys[idx];
		if(colName != 'id') {
			var addLabel = $('<label></label>');
			switch(type) {
				case 'text':
					var addInput = $('<textarea></textarea>');
					break;
				case 'str':
					var addInput = $('<input></input>');
					addInput.attr('type', 'text');
					break;
				case 'num':
					var addInput = $('<input></input>');
					addInput.attr('type', 'number');
					break;
				default:
					var addInput = $('<input></input>');
					break;
			}
			var idAddInput = idBase + '_input_' + colName;
			
			addLabel.attr('for', idAddInput);
			var req = required ? '*' : '';
			addLabel.text(colName + req);

			addInput.attr('id', idAddInput);
			addInput.attr('name', colName);
			$('#' + idAdd).append(addLabel);
			$('#' + idAdd).append($('<br/>'));

			$('#' + idAdd).append(addInput);
			$('#' + idAdd).append($('<br/>'));
		}

		var colHead = $('<td></td>');
		colHead.text(colName);
		$('#' + idList + '_head_row').append(colHead);
	}

	var addButton = $('<button></button>');
	addButton.attr('id', idAdd + '_btn');
	addButton.text('Create');
	addButton.on('click', function() {
		var data = {};
		for(var idx in keys) {
			var key = keys[idx];
			if(key == 'id') {
				continue;
			}

			data[key] = $('#' + idBase + '_input_' + key).val();
		}
		var endpoint = '/' + idBase + '_create';
		$.ajax({
			type: 'POST',
			url: endpoint, 
			data: data, 
			success: function(data) {
				data = JSON.parse(data);
				if('error' in data) {
					handleError(data);
					return;
				} 
				listWinaflJobs(data);
			}
		});
		console.log(data);
	});
	$('#' + idAdd).append(addButton);
}

function buildRun(runSchema) {
	var order = runSchema['order'];
	for(var idx in order) {
		var key = order[idx];
		console.log(key);
		var col = $('<td></td>');
		col.text(key);
		$('#run_list_head_row').append(col);
	}
}

function buildElements() {
	console.log(schema);
	for(var key in schema) {
		if(key.indexOf('job') > -1) {
			buildJob(schema, key);
		} else if(key == 'run') {
			buildRun(schema[key]);
		}
	}
}

function initPage() {
	$.getJSON('/schema', function(results) {
		schema = results;
		buildElements();
	});
}
