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

function runRun(run_id) {
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
			runRun(id);
		});
		row.append(startButton);

		killButton.on('click', function() {
			console.log('kill');
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

function handleError(data) {
	console.log('ERROR: ', data['message']);
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

$(document).ready(function() {
	initPage();
	fetchJobs();
	fetchRuns();
});
