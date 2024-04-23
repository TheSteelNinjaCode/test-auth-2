<?php

use Lib\Auth\Auth;
use Lib\Prisma\Classes\Prisma;
use Lib\Validator;
use Lib\StateManager;

$auth = new Auth();

if ($auth->isAuthenticated()) {
    redirect('/dashboard');
    exit;
}

$prisma = new Prisma();
$stateManager = new StateManager();
$message = '';
$name = "";
$email = "";
$password = "";

if ($isPost) {
    $name = Validator::validateString($_POST['name'] ?? '');
    $email = Validator::validateString($_POST['email'] ?? '');
    $password = Validator::validateString($_POST['password'] ?? '');

    $stateManager->setState(['post' => [
        'name' => $name,
        'email' => $email,
        'password' => $password
    ]], true);

    $userExist = $prisma->user->findUnique([
        'where' => [
            'email' => $email
        ]
    ]);

    if ($userExist) {
        $stateManager->setState(['register' => [
            'message' => 'User already exist'
        ]], true);
    } else {
        $prisma->user->create([
            'data' => [
                'name' => $name,
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'userRole' => [
                    'connectOrCreate' => [
                        'where' => [
                            'name' => 'User'
                        ],
                        'create' => [
                            'name' => 'User'
                        ]
                    ]
                ]
            ]
        ]);

        redirect('/login');
    }

    redirect('/register');
}

if ($stateManager->getState('register')) {
    $message = $stateManager->getState('register')['message'];
    $name = $stateManager->getState('post')['name'];
    $email = $stateManager->getState('post')['email'];
    $password = $stateManager->getState('post')['password'];
}

$stateManager->resetState(['register', 'post'], true);

?>


<div class="flex flex-col max-w-md px-4 py-8 bg-white rounded-lg shadow dark:bg-gray-800 sm:px-6 md:px-8 lg:px-10">
    <div class="self-center mb-2 text-xl font-light text-gray-800 sm:text-2xl dark:text-white">
        Create a new account
    </div>
    <span class="justify-center text-sm text-center text-gray-500 flex-items-center dark:text-gray-400">
        Already have an account ?
        <a href="/login" class="text-sm text-blue-500 underline hover:text-blue-700">
            Sign in
        </a>
    </span>
    <span class="text-red-500 text-center mt-4"><?= $message ?></span>
    <div class="p-6 mt-8">
        <form method="post">
            <div class="flex flex-col mb-2">
                <div class=" relative ">
                    <input type="text" id="create-account-name" class=" rounded-lg border-transparent flex-1 appearance-none border border-gray-300 w-full py-2 px-4 bg-white text-gray-700 placeholder-gray-400 shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-purple-600 focus:border-transparent" name="name" placeholder="Name" value="<?= $name ?>" />
                </div>
            </div>
            <div class="flex flex-col mb-2">
                <div class=" relative ">
                    <input type="text" id="create-account-email" class=" rounded-lg border-transparent flex-1 appearance-none border border-gray-300 w-full py-2 px-4 bg-white text-gray-700 placeholder-gray-400 shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-purple-600 focus:border-transparent" placeholder="Email" name="email" value="<?= $email ?>" />
                </div>
            </div>
            <div class="flex flex-col mb-2">
                <div class=" relative ">
                    <input type="password" id="create-account-password" class=" rounded-lg border-transparent flex-1 appearance-none border border-gray-300 w-full py-2 px-4 bg-white text-gray-700 placeholder-gray-400 shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-purple-600 focus:border-transparent" placeholder="Password" name="password" value="<?= $password ?>" />
                </div>
            </div>
            <div class="flex w-full my-4">
                <button type="submit" class="py-2 px-4  bg-purple-600 hover:bg-purple-700 focus:ring-purple-500 focus:ring-offset-purple-200 text-white w-full transition ease-in duration-200 text-center text-base font-semibold shadow-md focus:outline-none focus:ring-2 focus:ring-offset-2  rounded-lg ">
                    Register
                </button>
            </div>
        </form>
    </div>
</div>