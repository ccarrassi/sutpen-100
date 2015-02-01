function revealNav() {
	var el = document.getElementById('navigation');
	if (el.className == 'invisible') {
		el.className = 'nav-menu';
	} else if (el.className == 'nav-menu') {
		el.className = 'hidden';
	} else {
		el.className = 'nav-menu';
	}
};

function revealLeftArrow() {
	var el = document.getElementById('page');

	if (el.className == 0) {
		el.className = 'invisible';
	} else {
		el.className = 'left'
	}
};

function slideNew() {
	var el = document.getElementById('new');
	if (el.className == 'nav-button') {
		el.className = 'new-slide';
	} else if (el.className == 'new-slide') {
		el.className = 'new-chill';
	} else {
		el.className = 'new-slide'
	}
};

window.onload = function(){
var nav_button = document.getElementById('menu');
var new_button = document.getElementById('new-li');

new_button.addEventListener("click", slideNew, false);
nav_button.addEventListener("click", revealNav, false);
var what = revealLeftArrow
}
