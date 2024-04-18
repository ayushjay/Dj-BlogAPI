from rest_framework import permissions

"""The has_object_permission method, on the other hand, 
is used to determine if a user has permission to perform a certain action on a specific object. 
It first checks if the request method is one of the safe methods (GET, HEAD, or OPTIONS),
 which are typically read-only operations that do not modify data. If the request method is a safe method, it returns True, allowing access.

If the request method is not a safe method (i.e., it's a write operation), 
the method checks if the user making the request is the author of the object. If the user is the author, it returns True, allowing access; otherwise, it returns False, denying access.

To answer your question, if the request method is one of the safe methods, 
the method will indeed return True and will not reach the return obj.author == request.user line. 
This behavior is intentional and follows the design of the permission class, where safe methods are allowed for all users, 
while write operations are restricted to the author of the object.
"""


class IsAuthorOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        # Authenticated users only can see list view
        if request.user.is_authenticated:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request so we'll always
        # allow GET, HEAD, or OPTIONS requests
        if request.method in permissions.SAFE_METHODS:
            return True
        # Write permissions are only allowed to the author of a post
        return obj.author == request.user
