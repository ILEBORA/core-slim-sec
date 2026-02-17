
Criteria
OR (|) and AND (&)

!= (negative conditions)

multi-value matching (a,b,c)

checkbox / radio / multi-select support

graceful handling of missing fields

optional debug mode

safe clearing behavior

1. Supported Grammar (Clear Contract)
kind=parent|child           // OR
kind=parent&gender=F        // AND
kind!=spouse                // NOT
parenthood_type=birth,ivf  // IN list

How You Call It (Recommended)
$(document).on('change', 'form', function () {
    evaluateDependencies($(this));
});

$(document).ready(function () {
    $('form').each(function () {
        evaluateDependencies($(this));
    });
});


Optional debug:

evaluateDependencies($(this), true);

4. Why This Is a Big Upgrade (Without Being Heavy)
Before

Only |

Only =

Strings only

Silent failure

Fragile clearing

Now

Logical expressions

Safer parsing

Works with real form controls

Debuggable

Declarative and extensible

5. Example Rules You Can Now Use
'depends_on' => 'kind=parent&gender=F'

'depends_on' => 'kind!=spouse'

'depends_on' => 'parenthood_type=birth,ivf'

'depends_on' => 'kind=parent|child'